# File: sns_publisher.py

import json
import boto3
import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, ConnectTimeoutError


# Define the Boto3 configuration for production use
# This includes retries, timeouts, and connection settings
BOTO3_CONFIG = Config(
    # Retry configuration with exponential backoff
    retries={
        'total_max_attempts': 5,      # 1 initial + 4 retries
        'mode': 'standard'            # AWS recommended retry mode
    },
    # Timeout configurations
    connect_timeout=10,               # Connection timeout in seconds
    read_timeout=30,                  # Read timeout in seconds
    # Connection pool settings
    max_pool_connections=50,          # Max connections in pool
    # Region configuration (can be overridden)
    region_name=None,                 # Will use default region resolution
    # Security settings
    signature_version='v4',           # AWS Signature Version 4
    # User agent for debugging
    user_agent_extra='sr-security-logger/2.0'
)

# Failover configuration
FAILOVER_CONFIG = {
    'primary_timeout': 2,              # Fail fast on primary (2 seconds)
    'primary_retries': 2,              # Only 2 retries on primary before failover
    'failover_timeout': 5,             # More patient with failover (5 seconds)
    'failover_retries': 3,             # 3 retries on failover
    'circuit_breaker_threshold': 5,    # Open circuit after 5 consecutive failures
    'circuit_breaker_timeout': 60,     # Keep circuit open for 60 seconds
}


class CircuitBreaker:
    """Simple circuit breaker to prevent repeated attempts to failing region."""
    
    def __init__(self, threshold: int = 5, timeout: int = 60):
        self.threshold = threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.is_open = False
    
    def record_success(self):
        """Record successful request - reset circuit."""
        self.failure_count = 0
        self.is_open = False
        self.last_failure_time = None
    
    def record_failure(self):
        """Record failed request - may open circuit."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.threshold:
            self.is_open = True
    
    def should_attempt(self) -> bool:
        """Check if we should attempt to use this region."""
        if not self.is_open:
            return True
        
        # Check if enough time has passed to retry
        if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
            # Half-open: try again
            self.failure_count = max(0, self.failure_count - 1)
            self.is_open = False
            return True
        
        return False


class SNSPublisher:
    """
    A client for publishing security logs to AWS SNS with automatic regional failover.
    
    Features:
    - Automatic failover between primary and failover regions
    - Circuit breaker to prevent cascading failures
    - Fast-fail on primary to minimize latency
    - Metrics tracking for monitoring
    """

    def __init__(
        self, 
        topic_arn: str, 
        region_name: str = None,
        failover_topic_arn: Optional[str] = None,
        failover_region: Optional[str] = None,
        enable_failover: bool = True,
        test_mode: bool = False
    ):
        """
        Initialize SNS Publisher with optional failover support.
        
        Args:
            topic_arn: Primary SNS topic ARN
            region_name: Primary AWS region (default: us-west-2)
            failover_topic_arn: Failover SNS topic ARN (optional)
            failover_region: Failover AWS region (optional, default: us-east-2)
            enable_failover: Enable automatic failover (default: True)
            test_mode: Enable test mode (no actual publishing)
        """
        self.topic_arn = topic_arn
        self.test_mode = test_mode
        self.enable_failover = enable_failover and failover_topic_arn is not None
        
        # Failover configuration
        self.failover_topic_arn = failover_topic_arn
        self.failover_region = failover_region or "us-east-2"
        
        # Circuit breakers for each region
        self.primary_circuit = CircuitBreaker(
            threshold=FAILOVER_CONFIG['circuit_breaker_threshold'],
            timeout=FAILOVER_CONFIG['circuit_breaker_timeout']
        )
        
        # Metrics
        self.metrics = {
            'primary_success': 0,
            'primary_failure': 0,
            'failover_attempts': 0,
            'failover_success': 0,
            'failover_failure': 0,
            'total_failures': 0,
        }
        
        if not test_mode:
            # Primary region client
            if region_name is None:
                region_name = "us-west-2"  # Default region
            
            self.region_name = region_name
            
            # Create primary client with fast-fail config
            primary_config = Config(
                retries={
                    'total_max_attempts': FAILOVER_CONFIG['primary_retries'],
                    'mode': 'standard'
                },
                connect_timeout=FAILOVER_CONFIG['primary_timeout'],
                read_timeout=FAILOVER_CONFIG['primary_timeout'],
                max_pool_connections=BOTO3_CONFIG.max_pool_connections,
                signature_version=BOTO3_CONFIG.signature_version,
                user_agent_extra=BOTO3_CONFIG.user_agent_extra,
                region_name=region_name
            )
            
            self.sns_client = boto3.client('sns', config=primary_config)
            
            # Create failover client if enabled
            if self.enable_failover:
                failover_config = Config(
                    retries={
                        'total_max_attempts': FAILOVER_CONFIG['failover_retries'],
                        'mode': 'standard'
                    },
                    connect_timeout=FAILOVER_CONFIG['failover_timeout'],
                    read_timeout=FAILOVER_CONFIG['failover_timeout'],
                    max_pool_connections=BOTO3_CONFIG.max_pool_connections,
                    signature_version=BOTO3_CONFIG.signature_version,
                    user_agent_extra=BOTO3_CONFIG.user_agent_extra,
                    region_name=self.failover_region
                )
                
                self.failover_sns_client = boto3.client('sns', config=failover_config)
            else:
                self.failover_sns_client = None
        else:
            self.sns_client = None
            self.failover_sns_client = None
            self.region_name = region_name or "us-west-2"

    def _is_retriable_error(self, error: Exception) -> bool:
        """Determine if an error should trigger failover."""
        # Network errors, timeouts, and service unavailable should trigger failover
        retriable_exceptions = (
            EndpointConnectionError,
            ConnectTimeoutError,
        )
        
        if isinstance(error, retriable_exceptions):
            return True
        
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
            # Throttling, service errors, and timeouts should trigger failover
            if error_code in ['Throttling', 'ServiceUnavailable', 'RequestTimeout', 'TooManyRequestsException']:
                return True
        
        return False

    def _publish_to_region(
        self, 
        client, 
        topic_arn: str, 
        message: str,
        region_name: str
    ) -> Dict[str, str]:
        """Attempt to publish to a specific region."""
        try:
            client.publish(
                TopicArn=topic_arn,
                Message=message,
            )
            return {"status": "success", "region": region_name}
        except Exception as e:
            return {
                "status": "failure",
                "region": region_name,
                "error": str(e),
                "retriable": self._is_retriable_error(e)
            }

    def publish_message(self, log_details: Dict[str, Any]) -> Dict[str, str]:
        """
        Publishes a single JSON log message with automatic failover.
        
        Failover Logic:
        1. Try primary region (fast-fail)
        2. If primary fails with retriable error, try failover region
        3. Circuit breaker prevents repeated attempts to failing regions
        
        Args:
            log_details: Dictionary containing the log data to publish
        
        Returns:
            Dict with "status" key ("success" or "failure") and optional metadata.
        """
        try:
            # Add a timestamp to the log record if not already present
            if 'timestamp' not in log_details or not log_details['timestamp']:
                log_details['timestamp'] = datetime.now(timezone.utc).isoformat()

            # The message must be a JSON string
            message = json.dumps(log_details, indent=2)

            if self.test_mode:
                # In test mode, log safe summary information
                print("🧪 TEST MODE - Would send to SNS:")
                print(f"📍 Primary Topic: {self.topic_arn}")
                if self.enable_failover:
                    print(f"📍 Failover Topic: {self.failover_topic_arn}")
                print(f"📦 Message size: {len(message)} characters")
                print(f"📦 Event type: {log_details.get('event_type', 'unknown')}")
                print("=" * 60)
                return {"status": "success", "test_mode": True, "message_size": len(message)}
            
            # Try primary region if circuit is closed
            if self.primary_circuit.should_attempt():
                result = self._publish_to_region(
                    self.sns_client,
                    self.topic_arn,
                    message,
                    self.region_name
                )
                
                if result["status"] == "success":
                    self.primary_circuit.record_success()
                    self.metrics['primary_success'] += 1
                    return {"status": "success", "region": self.region_name}
                
                # Primary failed
                self.metrics['primary_failure'] += 1
                
                # Check if error is retriable and failover is enabled
                if not result.get('retriable', False) or not self.enable_failover:
                    # Non-retriable error or no failover available
                    self.primary_circuit.record_failure()
                    self.metrics['total_failures'] += 1
                    return {
                        "status": "failure",
                        "message": f"Primary region failed: {result.get('error', 'Unknown error')}",
                        "region": self.region_name
                    }
                
                # Record failure and try failover
                self.primary_circuit.record_failure()
            
            # Try failover region
            if self.enable_failover and self.failover_sns_client:
                self.metrics['failover_attempts'] += 1
                
                result = self._publish_to_region(
                    self.failover_sns_client,
                    self.failover_topic_arn,
                    message,
                    self.failover_region
                )
                
                if result["status"] == "success":
                    self.metrics['failover_success'] += 1
                    return {
                        "status": "success",
                        "region": self.failover_region,
                        "failover": True
                    }
                
                # Failover also failed
                self.metrics['failover_failure'] += 1
                self.metrics['total_failures'] += 1
                
                return {
                    "status": "failure",
                    "message": f"Both regions failed. Primary: skipped/failed, Failover: {result.get('error', 'Unknown error')}",
                    "primary_region": self.region_name,
                    "failover_region": self.failover_region
                }
            
            # Failover not enabled but primary failed
            self.metrics['total_failures'] += 1
            return {
                "status": "failure",
                "message": "Primary region unavailable and failover not enabled",
                "region": self.region_name
            }
            
        except Exception as e:
            # Unexpected error
            self.metrics['total_failures'] += 1
            error_message = f"Unexpected error publishing security log: {str(e)}"
            return {"status": "failure", "message": error_message}
    
    def get_metrics(self) -> Dict[str, int]:
        """Get current metrics for monitoring."""
        return self.metrics.copy()
    
    def reset_metrics(self):
        """Reset metrics counters."""
        self.metrics = {
            'primary_success': 0,
            'primary_failure': 0,
            'failover_attempts': 0,
            'failover_success': 0,
            'failover_failure': 0,
            'total_failures': 0,
        }
