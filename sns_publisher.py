# File: sns_publisher.py
"""
AWS SNS Publisher Module

A client for publishing security logs to AWS SNS with automatic regional failover.

Features:
    - Hot start optimization (SNS client reused across invocations)
    - Automatic failover between primary and failover regions
    - Circuit breaker to prevent cascading failures
    - Message batching for large payloads (SNS 256KB limit)
    - UUID generation for event correlation

Example:
    >>> from sns_publisher import SNSPublisher
    >>> 
    >>> # Initialize once (typically at module level for Lambda)
    >>> publisher = SNSPublisher(
    ...     topic_arn="arn:aws:sns:us-west-2:123456789012:my-topic",
    ...     region_name="us-west-2",
    ...     failover_topic_arn="arn:aws:sns:us-east-2:123456789012:my-failover",
    ...     failover_region="us-east-2",
    ...     enable_failover=True
    ... )
    >>> 
    >>> # Reuse for all publish operations
    >>> result = publisher.publish_message(log_data)
"""

import json
import boto3
import time
import uuid
import sys
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, ConnectTimeoutError


# SNS message size limit in bytes (256 KB)
SNS_MAX_MESSAGE_SIZE = 256 * 1024

# Safety margin to account for JSON overhead and metadata
SNS_SAFE_MESSAGE_SIZE = 250 * 1024


# Define the Boto3 configuration for production use
BOTO3_CONFIG = Config(
    retries={
        'total_max_attempts': 5,
        'mode': 'standard'
    },
    connect_timeout=10,
    read_timeout=30,
    max_pool_connections=50,
    region_name=None,
    signature_version='v4',
    user_agent_extra='sr-security-logger/3.0'
)

# Failover configuration
FAILOVER_CONFIG = {
    'primary_timeout': 2,
    'primary_retries': 2,
    'failover_timeout': 5,
    'failover_retries': 3,
    'circuit_breaker_threshold': 5,
    'circuit_breaker_timeout': 60,
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
    
    **HOT START OPTIMIZATION**: This class is designed to be instantiated once and reused
    across multiple invocations. The SNS client is created during initialization and
    maintained for the lifetime of the instance, eliminating cold start overhead.
    
    Features:
        - Automatic failover between primary and failover regions
        - Circuit breaker to prevent cascading failures
        - Fast-fail on primary to minimize latency
        - Message batching for large payloads (SNS 256KB limit)
        - UUID generation for event correlation
        - Metrics tracking for monitoring
        - Optional explicit IAM User credentials support
    
    Example:
        >>> # Initialize once (typically at module level for Lambda)
        >>> publisher = SNSPublisher(
        ...     topic_arn="arn:aws:sns:us-west-2:123456789012:my-topic",
        ...     region_name="us-west-2",
        ...     failover_topic_arn="arn:aws:sns:us-east-2:123456789012:my-failover",
        ...     enable_failover=True
        ... )
        >>> 
        >>> # Reuse for all publish operations
        >>> result = publisher.publish_message(log_data)
    """

    def __init__(
        self, 
        topic_arn: str, 
        region_name: str = None,
        failover_topic_arn: Optional[str] = None,
        failover_region: Optional[str] = None,
        enable_failover: bool = True,
        test_mode: bool = False,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None
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
            aws_access_key_id: Optional AWS access key ID for IAM User authentication
            aws_secret_access_key: Optional AWS secret access key for IAM User authentication
            aws_session_token: Optional AWS session token for temporary credentials
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
        
        # Build credentials kwargs if provided (for IAM User authentication)
        credentials_kwargs = {}
        if aws_access_key_id and aws_secret_access_key:
            credentials_kwargs = {
                'aws_access_key_id': aws_access_key_id,
                'aws_secret_access_key': aws_secret_access_key,
            }
            if aws_session_token:
                credentials_kwargs['aws_session_token'] = aws_session_token
        
        if not test_mode:
            # Primary region client
            if region_name is None:
                region_name = "us-west-2"  # Default region
                
            self.region_name = region_name
            
            # Create primary client with fast-fail config (HOT START - reused across invocations)
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
            
            self.sns_client = boto3.client('sns', config=primary_config, **credentials_kwargs)
            
            # Create failover client if enabled (HOT START - reused across invocations)
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
                
                self.failover_sns_client = boto3.client('sns', config=failover_config, **credentials_kwargs)
            else:
                self.failover_sns_client = None
        else:
            self.sns_client = None
            self.failover_sns_client = None
            self.region_name = region_name or "us-west-2"

    def generate_event_uuid(self) -> str:
        """
        Generate a UUID v4 for event correlation.
        
        Returns:
            str: A UUID v4 string
        """
        return str(uuid.uuid4())

    def _get_message_size(self, message: str) -> int:
        """Calculate the size of a message in bytes."""
        return len(message.encode('utf-8'))

    def _batch_id_list(
        self, 
        base_log_details: Dict[str, Any], 
        id_list: List[str], 
        event_uuid: str
    ) -> List[Dict[str, Any]]:
        """
        Split a large id_list into batches that fit within SNS message size limits.
        
        Args:
            base_log_details: The base log event (without id_list)
            id_list: The full list of IDs to batch
            event_uuid: UUID for event correlation
            
        Returns:
            List of batched log events
        """
        # Start with just the base event (without id_list) to calculate overhead
        base_event = {k: v for k, v in base_log_details.items() if k != 'id_list'}
        base_message_size = self._get_message_size(json.dumps(base_event, indent=2))
        
        # Calculate available space for id_list
        id_list_overhead = 100  # Extra bytes for id_list field and part metadata
        available_space = SNS_SAFE_MESSAGE_SIZE - base_message_size - id_list_overhead
        
        if available_space <= 0:
            raise ValueError('Base log event is too large to fit in SNS message')
        
        # Calculate approximate IDs per batch
        avg_id_size = len(json.dumps(id_list)) / len(id_list) if id_list else 50
        ids_per_batch = max(1, int(available_space / avg_id_size))
        
        # Split into batches
        batches = []
        for i in range(0, len(id_list), ids_per_batch):
            batch_id_list = id_list[i:i + ids_per_batch]
            batch_number = len(batches) + 1
            
            batch_event = {
                **base_log_details,
                'id_list': batch_id_list,
                'record_count': len(batch_id_list),
                'event_uuid': event_uuid,
                'part_number': batch_number,
                'total_parts': -1,  # Will be updated after all batches are created
                'total_record_count': len(id_list)  # Total across all batches
            }
            
            # Verify batch fits
            batch_message = json.dumps(batch_event, indent=2)
            if self._get_message_size(batch_message) > SNS_SAFE_MESSAGE_SIZE:
                # Reduce batch size and retry
                reduced_ids_per_batch = max(1, ids_per_batch // 2)
                if reduced_ids_per_batch < ids_per_batch:
                    reduced_batch = id_list[i:i + reduced_ids_per_batch]
                    reduced_event = {
                        **base_log_details,
                        'id_list': reduced_batch,
                        'record_count': len(reduced_batch),
                        'event_uuid': event_uuid,
                        'part_number': len(batches) + 1,
                        'total_parts': -1,
                        'total_record_count': len(id_list)
                    }
                    batches.append(reduced_event)
                    # Adjust loop counter
                    i = i + reduced_ids_per_batch - ids_per_batch
                    continue
            
            batches.append(batch_event)
        
        # Update total_parts for all batches
        for idx, batch in enumerate(batches):
            batch['total_parts'] = len(batches)
            batch['part_number'] = idx + 1
        
        return batches

    def _is_retriable_error(self, error: Exception) -> bool:
        """Determine if an error should trigger failover."""
        retriable_exceptions = (
            EndpointConnectionError,
            ConnectTimeoutError,
        )
        
        if isinstance(error, retriable_exceptions):
            return True
        
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
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
        Publishes a single JSON log message with automatic failover and batching.
        
        Failover Logic:
            1. Try primary region (fast-fail)
            2. If primary fails with retriable error, try failover region
            3. Circuit breaker prevents repeated attempts to failing regions

        Batching Logic:
            - If message exceeds SNS size limit (256KB), automatically batches
            - Each batch includes event_uuid, part_number, total_parts for correlation
            - record_count is calculated automatically from id_list

        Args:
            log_details: Dictionary containing the log data to publish

        Returns:
            Dict with "status" key ("success" or "failure") and optional metadata.
            
        Example:
            >>> result = publisher.publish_message({
            ...     'event_type': 'login_attempt',
            ...     'status': 'status.general.success',
            ...     'actor_identifier': 'user@company.com',
            ...     # ... other fields
            ... })
            >>> if result['status'] == 'success':
            ...     print(f"Published to {result.get('region')}")
        """
        try:
            # Generate UUID for this event (used for correlation across batches)
            event_uuid = log_details.get('event_uuid') or self.generate_event_uuid()
            log_details['event_uuid'] = event_uuid
            
            # Add a timestamp to the log record if not already present
            if 'timestamp' not in log_details or not log_details['timestamp']:
                log_details['timestamp'] = datetime.now(timezone.utc).isoformat()

            # Check if we need to batch (id_list present and message too large)
            messages_to_publish = [log_details]
            
            if 'id_list' in log_details and isinstance(log_details['id_list'], list):
                message = json.dumps(log_details, indent=2)
                if self._get_message_size(message) > SNS_SAFE_MESSAGE_SIZE:
                    messages_to_publish = self._batch_id_list(log_details, log_details['id_list'], event_uuid)
                else:
                    # Single message, add part fields for consistency
                    log_details['part_number'] = 1
                    log_details['total_parts'] = 1
                    log_details['record_count'] = len(log_details['id_list'])
                    log_details['total_record_count'] = len(log_details['id_list'])

            # Publish all messages (batched or single)
            results = []
            
            for message_data in messages_to_publish:
                message = json.dumps(message_data, indent=2)

                if self.test_mode:
                    # Test mode: capture message without logging sensitive data
                    results.append({
                        "status": "success",
                        "test_mode": True,
                        "message_content": message
                    })
                    continue
                
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
                        results.append({
                            "status": "success",
                            "region": self.region_name,
                            "event_uuid": message_data.get('event_uuid'),
                            "part_number": message_data.get('part_number'),
                            "total_parts": message_data.get('total_parts')
                        })
                        continue
                    
                    # Primary failed
                    self.metrics['primary_failure'] += 1
                    
                    # Check if error is retriable and failover is enabled
                    if not result.get('retriable', False) or not self.enable_failover:
                        self.primary_circuit.record_failure()
                        self.metrics['total_failures'] += 1
                        results.append({
                            "status": "failure",
                            "message": f"Primary region failed: {result.get('error', 'Unknown error')}",
                            "region": self.region_name,
                            "event_uuid": message_data.get('event_uuid'),
                            "part_number": message_data.get('part_number'),
                            "total_parts": message_data.get('total_parts')
                        })
                        continue
                    
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
                        results.append({
                            "status": "success",
                            "region": self.failover_region,
                            "failover": True,
                            "event_uuid": message_data.get('event_uuid'),
                            "part_number": message_data.get('part_number'),
                            "total_parts": message_data.get('total_parts')
                        })
                        continue
                    
                    # Failover also failed
                    self.metrics['failover_failure'] += 1
                    self.metrics['total_failures'] += 1
                    
                    results.append({
                        "status": "failure",
                        "message": f"Both regions failed. Primary: skipped/failed, Failover: {result.get('error', 'Unknown error')}",
                        "primary_region": self.region_name,
                        "failover_region": self.failover_region,
                        "event_uuid": message_data.get('event_uuid'),
                        "part_number": message_data.get('part_number'),
                        "total_parts": message_data.get('total_parts')
                    })
                    continue
                
                # Failover not enabled but primary failed
                self.metrics['total_failures'] += 1
                results.append({
                    "status": "failure",
                    "message": "Primary region unavailable and failover not enabled",
                    "region": self.region_name,
                    "event_uuid": message_data.get('event_uuid'),
                    "part_number": message_data.get('part_number'),
                    "total_parts": message_data.get('total_parts')
                })
            
            # Return aggregated result
            failures = [r for r in results if r.get('status') == 'failure']
            if failures:
                return {
                    "status": "failure",
                    "message": f"{len(failures)}/{len(results)} messages failed to publish",
                    "event_uuid": event_uuid,
                    "total_parts": len(results)
                }
            
            return {
                "status": "success",
                "region": results[0].get('region') if results else None,
                "failover": results[0].get('failover') if results else None,
                "test_mode": results[0].get('test_mode') if results else None,
                "event_uuid": event_uuid,
                "total_parts": len(results)
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
