#!/usr/bin/env python3
"""
Example usage of the sr-sec-py-sns-logger module.
This demonstrates the simplest way to integrate security logging.
"""

import os
import security_logging_sns
from security_log_fields import AuthorizationStatus, UserType

def main():
    """Example of how to use the security logging module."""
    
    # Step 1: Initialize security logging (do this once at app startup)
    # This will automatically read environment variables
    try:
        security_logging_sns.init_security_logging()
        print("✅ Security logging initialized successfully")
    except ValueError as e:
        print(f"❌ Failed to initialize: {e}")
        print("💡 Make sure SECURITY_LOGS_TOPIC_ARN environment variable is set")
        return
    
    # Step 2: Define base log details (common to all events in this execution)
    base_log_details = {
        "service_name": "example-service",
        "cloud_service_api_type": "aws_lambda",
        "cloud_env_type": os.environ.get("ENV_TYPE", "dev"),
        "cloud_env_name": os.environ.get("ENV_NAME", "dev-env"),
        "service_account_id": os.environ.get("SERVICE_ACCOUNT_ID", "123456789012")
    }
    
    # Step 3: Log security events - it's that simple!
    
    # Example 1: User login success
    result = security_logging_sns.log_user_login(
        base_log_details=base_log_details,
        status=AuthorizationStatus.SUCCESS,
        session_id="session-12345",
        user_identifier="user@example.com",
        user_type=UserType.INTERNAL,
        source_ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (compatible)",
        user_role="admin"
    )
    
    if result["status"] == "success":
        print("✅ Login event logged successfully")
    else:
        print(f"❌ Login logging failed: {result.get('message')}")
    
    # Example 2: API request
    result = security_logging_sns.log_api_request_processed(
        base_log_details=base_log_details,
        source_ip_address="192.168.1.100",
        auth_protocol="oauth2_jwt",
        client_id="client-app-123",
        client_type="web_application",
        endpoint_path="/api/v1/users",
        http_method="GET",
        authorization_status="Success",
        endpoint_sensitivity="confidential"
    )
    
    if result["status"] == "success":
        print("✅ API request event logged successfully")
    else:
        print(f"❌ API request logging failed: {result.get('message')}")

if __name__ == "__main__":
    main()
