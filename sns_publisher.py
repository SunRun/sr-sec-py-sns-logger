# File: sns_publisher.py

import json
import boto3
from typing import Dict, Any
from datetime import datetime, timezone
from botocore.config import Config


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
    user_agent_extra='sr-security-logger/1.0'
)


class SNSPublisher:
    """A client for publishing security logs to an AWS SNS topic."""

    def __init__(self, topic_arn: str, region_name: str = None, test_mode: bool = False):
        self.topic_arn = topic_arn
        self.test_mode = test_mode
        
        if not test_mode:
            # Always create a config with region specified (either provided or default us-west-2)
            if region_name is None:
                region_name = "us-west-2"  # Default region
                
            config = Config(
                retries=BOTO3_CONFIG.retries,
                connect_timeout=BOTO3_CONFIG.connect_timeout,
                read_timeout=BOTO3_CONFIG.read_timeout,
                max_pool_connections=BOTO3_CONFIG.max_pool_connections,
                signature_version=BOTO3_CONFIG.signature_version,
                user_agent_extra=BOTO3_CONFIG.user_agent_extra,
                region_name=region_name
            )
            
            # Initialize the SNS client with comprehensive configuration
            self.sns_client = boto3.client('sns', config=config)
        else:
            self.sns_client = None

    def publish_message(self, log_details: Dict[str, Any]) -> Dict[str, str]:
        """
        Publishes a single JSON log message to the configured SNS topic.
        Includes base and event-specific details with built-in AWS retry logic.

        Args:
            log_details: Dictionary containing the log data to publish

        Returns:
            Dict with "status" key ("success" or "failure") and optional "message" key on failure.
        """
        try:
            # Add a timestamp to the log record if not already present
            if 'timestamp' not in log_details or not log_details['timestamp']:
                log_details['timestamp'] = datetime.now(timezone.utc).isoformat()

            # The message must be a JSON string
            message = json.dumps(log_details, indent=2)

            if self.test_mode:
                # In test mode, log safe summary information without exposing sensitive data
                print("🧪 TEST MODE - Would send to SNS:")
                print(f"📍 Topic ARN: {self.topic_arn}")
                print(f"📦 Message size: {len(message)} characters")
                print(f"📦 Event type: {log_details.get('event_type', 'unknown')}")
                print(f"📦 Actor type: {log_details.get('actor_type', 'unknown')}")
                print("=" * 60)
                return {"status": "success", "test_mode": True, "message_size": len(message)}
            else:
                # Publish the message to the SNS topic
                # AWS SDK will automatically handle retries according to RETRY_CONFIG
                self.sns_client.publish(
                    TopicArn=self.topic_arn,
                    Message=message,
                )
                return {"status": "success"}
        except Exception as e:
            # Handle potential SNS publishing errors (e.g., permissions, topic not found)
            # The built-in retries will have already been attempted at this point.
            error_message = f"Error publishing security log to SNS after retries: {str(e)}"
            return {"status": "failure", "message": error_message}
