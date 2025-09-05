#!/usr/bin/env python3
"""
Test script to demonstrate security logging without actually sending to SNS.
This captures and displays the log messages that would be sent.
"""

import security_logging_sns
from security_log_fields import AuthorizationStatus, UserType, ActionType

def main():
    """Test the security logging module in test mode."""
    
    print("🚀 Testing Security Logging Module")
    print("=" * 50)
    
    # Initialize in test mode - no AWS credentials needed!
    security_logging_sns.init_security_logging(test_mode=True)
    print("✅ Security logging initialized in TEST MODE\n")
    
    # Define base log details (common to all events)
    base_log_details = {
        "service_name": "test-service",
        "cloud_service_api_type": "aws_lambda", 
        "cloud_env_type": "dev",
        "cloud_env_name": "test-environment",
        "service_account_id": "123456789012",
        "aws_request_id": "test-request-123",
        "function_name": "test-function"
    }
    
    print("🧪 TEST 1: User Login Success Event")
    result = security_logging_sns.log_user_login(
        base_log_details=base_log_details,
        status=AuthorizationStatus.SUCCESS,
        session_id="session-abc123",
        user_identifier="test.user@company.com",
        user_type=UserType.INTERNAL,
        source_ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        user_role="developer",
        device_id="device-xyz789",
        context="web_application"
    )
    print(f"Result: {result}\n")
    
    print("🧪 TEST 2: User Login Failure Event")
    result = security_logging_sns.log_user_login(
        base_log_details=base_log_details,
        status=AuthorizationStatus.FAILURE,
        session_id="session-def456",
        user_identifier="bad.actor@external.com",
        user_type=UserType.CUSTOMER,
        source_ip_address="203.0.113.42",
        user_agent="curl/7.68.0",
        user_role="guest",
        reason="invalid_credentials"
    )
    print(f"Result: {result}\n")
    
    print("🧪 TEST 3: API Request Event")
    result = security_logging_sns.log_api_request_processed(
        base_log_details=base_log_details,
        source_ip_address="192.168.1.100",
        auth_protocol="oauth2_jwt",
        client_id="mobile-app-v2.1",
        client_type="mobile_application",
        endpoint_path="/api/v1/users/profile",
        http_method="GET",
        authorization_status="Success",
        endpoint_sensitivity="confidential",
        session_id="session-abc123"
    )
    print(f"Result: {result}\n")
    
    print("🧪 TEST 4: Single Record Access Event")
    result = security_logging_sns.log_single_record_access(
        base_log_details=base_log_details,
        user_identifier="test.user@company.com",
        source_ip_address="192.168.1.100",
        customer_id="customer-12345",
        action_type=ActionType.VIEWED,
        fields_accessed=["name", "email", "phone", "address"],
        session_id="session-abc123",
        actor_user_type=UserType.INTERNAL
    )
    print(f"Result: {result}\n")
    
    print("🧪 TEST 5: Permission Change Event")
    result = security_logging_sns.log_permission_change(
        base_log_details=base_log_details,
        actor_user_identifier="admin@company.com",
        target_user_identifier="test.user@company.com",
        session_id="session-admin-789",
        object_changed="user_role",
        previous_value="developer",
        new_value="senior_developer"
    )
    print(f"Result: {result}\n")
    
    print("🎉 All tests completed successfully!")
    print("📝 The above messages show exactly what would be sent to SNS in production.")

if __name__ == "__main__":
    main()
