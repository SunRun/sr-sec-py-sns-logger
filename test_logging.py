#!/usr/bin/env python3
"""
Test script to demonstrate the refactored security logging with new schema validation.
This captures and displays the log messages that would be sent, including validation failures.
"""

import security_logging_sns
from security_log_fields import (
    Status, ActorType, LogCategory, EventType, AuthProtocol, Detail, MfaType,
    HttpMethod, CloudEnvType, CloudServiceApiType, DataSensitivityLevel,
    EndpointSensitivity, InviteStatus, UserRole
)

def main():
    """Test the security logging module in test mode with new schema."""
    
    print("🚀 Testing Refactored Security Logging Module with New Schema")
    print("=" * 70)
    
    # Initialize in test mode - no AWS credentials needed!
    security_logging_sns.init_security_logging(test_mode=True)
    print("✅ Security logging initialized in TEST MODE\n")
    
    # Test 1: Valid User Login Success Event
    print("🧪 TEST 1: Valid User Login Success Event")
    result = security_logging_sns.log_user_login(
        # Base log fields
        actor_identifier="user123@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-abc123",
        cloud_env_type=CloudEnvType.DEV,
        service_name="test-service",
        cloud_env_unique_id="123456789012",
        cloud_env_name="test-environment",
        service_account_id="sa-log-writer@project.iam.gserviceaccount.com",
        source_ip_address="192.168.1.100",
        cloud_service_api_type=CloudServiceApiType.AWS_LAMBDA,
        # Event-specific fields
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        user_role=UserRole.ADMIN,
        detail="1st time login",
        device_id="device-xyz789",
        login_successful=True
    )
    print(f"Result: {result}\n")
    
    # Test 2: User Login with Missing Required Fields (should fail validation)
    print("🧪 TEST 2: User Login with Missing Required Fields (Validation Failure)")
    result = security_logging_sns.log_user_login(
        # Missing several required base fields
        actor_identifier="user123@company.com",
        # Missing actor_type, session_id, etc.
        user_agent="Mozilla/5.0",
        user_role="developer",
        detail=Detail.INVALID_CREDENTIALS,
        login_successful=False
    )
    print(f"Result: {result}\n")
    
    # Test 3: User Login with Missing Event-Specific Fields
    print("🧪 TEST 3: User Login with Missing Event-Specific Fields")
    result = security_logging_sns.log_user_login(
        # All base fields provided
        actor_identifier="user123@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-abc123",
        cloud_env_type=CloudEnvType.DEV,
        service_name="test-service",
        cloud_env_unique_id="123456789012",
        cloud_env_name="test-environment",
        service_account_id="sa-log-writer@project.iam.gserviceaccount.com",
        # Missing required event-specific fields (user_agent, user_role, detail)
        login_successful=False
    )
    print(f"Result: {result}\n")
    
    # Test 4: Valid MFA Challenge Event
    print("🧪 TEST 4: Valid MFA Challenge Success Event")
    result = security_logging_sns.log_mfa_challenge(
        # Base log fields
        actor_identifier="user456@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-def456",
        cloud_env_type=CloudEnvType.PROD,
        service_name="auth-service",
        cloud_env_unique_id="987654321098",
        cloud_env_name="production",
        service_account_id="sa-auth@project.iam.gserviceaccount.com",
        source_ip_address="203.0.113.42",
        cloud_service_api_type=CloudServiceApiType.GKE_NAMESPACE,
        # Event-specific fields
        user_agent="Mobile App v2.1",
        user_role=UserRole.SALES_REP,
        detail="login with a successful MFA",
        mfa_type=MfaType.OKTA_VERIFY,
        device_id="mobile-device-123",
        challenge_successful=True
    )
    print(f"Result: {result}\n")
    
    # Test 5: Valid API Request Event
    print("🧪 TEST 5: Valid API Request Success Event")
    result = security_logging_sns.log_api_request_processed(
        # Base log fields
        actor_identifier="api-client-xyz",
        actor_type=ActorType.SERVICE_INTERNAL,
        session_id="api-session-789",
        cloud_env_type=CloudEnvType.PROD,
        service_name="api-gateway",
        cloud_env_unique_id="555666777888",
        cloud_env_name="production-api",
        service_account_id="sa-api@project.iam.gserviceaccount.com",
        source_ip_address="10.0.1.50",
        cloud_service_api_type=CloudServiceApiType.AWS_LAMBDA,
        # Event-specific fields
        auth_protocol=AuthProtocol.OAUTH2_JWT,
        endpoint_path="/api/v1/users/profile",
        http_method=HttpMethod.GET,
        endpoint_sensitivity=EndpointSensitivity.CONFIDENTIAL,
        detail="Successful API call",
        request_successful=True
    )
    print(f"Result: {result}\n")
    
    # Test 6: Valid Multi-Record Access Event
    print("🧪 TEST 6: Valid Multi-Record Access Event")
    result = security_logging_sns.log_multi_record_access(
        # Base log fields
        actor_identifier="analyst@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-analyst-001",
        cloud_env_type=CloudEnvType.PROD,
        service_name="data-service",
        cloud_env_unique_id="111222333444",
        cloud_env_name="production-data",
        service_account_id="sa-data@project.iam.gserviceaccount.com",
        source_ip_address="192.168.2.100",
        # Event-specific fields
        endpoint_path="/api/v1/customers/bulk-export",
        data_sensitivity_level=DataSensitivityLevel.PII_BASIC,
        record_count=250,
        customer_id_list=["cust-001", "cust-002", "cust-003"],
        action_type="export"
    )
    print(f"Result: {result}\n")
    
    # Test 7: Valid Permission Change Event
    print("🧪 TEST 7: Valid Permission Change Event")
    result = security_logging_sns.log_permission_change(
        # Base log fields
        actor_identifier="admin@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-admin-002",
        cloud_env_type=CloudEnvType.PROD,
        service_name="user-management",
        cloud_env_unique_id="999888777666",
        cloud_env_name="production-mgmt",
        service_account_id="sa-mgmt@project.iam.gserviceaccount.com",
        # Event-specific fields
        target_user_identifier="developer@company.com",
        object_changed="Role",
        previous_value="developer",
        new_value="senior_developer",
        change_type="granted"
    )
    print(f"Result: {result}\n")
    
    # Test 8: Valid User Invite Event
    print("🧪 TEST 8: Valid User Invite Event")
    result = security_logging_sns.log_user_invite_event(
        # Base log fields
        actor_identifier="hr@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-hr-003",
        cloud_env_type=CloudEnvType.PROD,
        service_name="hr-system",
        cloud_env_unique_id="444555666777",
        cloud_env_name="production-hr",
        service_account_id="sa-hr@project.iam.gserviceaccount.com",
        # Event-specific fields
        target_user_email="newuser@company.com",
        assigned_role="developer",
        invite_status=InviteStatus.SENT
    )
    print(f"Result: {result}\n")
    
    # Test 9: Valid MFA Status Change Event
    print("🧪 TEST 9: Valid MFA Status Change Event")
    result = security_logging_sns.log_mfa_status_change(
        # Base log fields
        actor_identifier="security-admin@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="session-sec-004",
        cloud_env_type=CloudEnvType.PROD,
        service_name="security-service",
        cloud_env_unique_id="777888999000",
        cloud_env_name="production-sec",
        service_account_id="sa-security@project.iam.gserviceaccount.com",
        # Event-specific fields
        target_object="user789@company.com",
        mfa_id="mfa-device-456",
        change_type="enabled"
    )
    print(f"Result: {result}\n")
    
    # Test 10: Test with completely empty parameters (should show all missing fields)
    print("🧪 TEST 10: Completely Empty Parameters (Maximum Validation Failure)")
    result = security_logging_sns.log_user_login()
    print(f"Result: {result}\n")
    
    # Test 11: User Login Failure with Standardized Detail Values
    print("🧪 TEST 11: User Login Failure with Standardized Detail Values")
    result = security_logging_sns.log_user_login(
        # Base log fields
        actor_identifier="attacker@external.com",
        actor_type=ActorType.HUMAN_CUSTOMER,
        session_id="session-failed-123",
        cloud_env_type=CloudEnvType.PROD,
        service_name="auth-service",
        cloud_env_unique_id="123456789012",
        cloud_env_name="production",
        service_account_id="sa-auth@project.iam.gserviceaccount.com",
        source_ip_address="203.0.113.42",
        cloud_service_api_type=CloudServiceApiType.AWS_LAMBDA,
        # Event-specific fields
        user_agent="curl/7.68.0",
        user_role=UserRole.CUSTOMER_USER,
        detail=Detail.INVALID_CREDENTIALS,
        login_successful=False
    )
    print(f"Result: {result}\n")
    
    # Test 12: Test with non-standardized values (should fail validation)
    print("🧪 TEST 12: Non-Standardized Values (Validation Failure)")
    result = security_logging_sns.log_user_login(
        # Base log fields with invalid actor_type
        actor_identifier="user@company.com",
        actor_type="invalid_actor_type",  # This should fail validation
        session_id="session-abc123",
        cloud_env_type=CloudEnvType.DEV,
        service_name="test-service",
        cloud_env_unique_id="123456789012",
        cloud_env_name="test-environment",
        service_account_id="sa-log-writer@project.iam.gserviceaccount.com",
        # Event-specific fields
        user_agent="Mozilla/5.0",
        user_role="invalid_role",  # This should fail validation
        detail="1st time login",
        login_successful=True
    )
    print(f"Result: {result}\n")
    
    # Test 13: Test API request with invalid protocol (should fail validation)
    print("🧪 TEST 13: API Request with Invalid Protocol (Validation Failure)")
    result = security_logging_sns.log_api_request_processed(
        # Base log fields
        actor_identifier="api-client-xyz",
        actor_type=ActorType.SERVICE_INTERNAL,
        session_id="api-session-789",
        cloud_env_type=CloudEnvType.PROD,
        service_name="api-gateway",
        cloud_env_unique_id="555666777888",
        cloud_env_name="production-api",
        service_account_id="sa-api@project.iam.gserviceaccount.com",
        source_ip_address="10.0.1.50",
        # Event-specific fields with invalid values
        auth_protocol="invalid_protocol",  # This should fail validation
        endpoint_path="/api/v1/users/profile",
        http_method="INVALID_METHOD",  # This should fail validation
        endpoint_sensitivity="invalid_sensitivity",  # This should fail validation
        detail="Successful API call",
        request_successful=True
    )
    print(f"Result: {result}\n")
    
    print("🎉 All tests completed!")
    print("📝 The above tests demonstrate:")
    print("   ✅ Valid events with proper base_log and log_specifics fields")
    print("   ❌ Validation failures for missing required base_log fields")
    print("   ❌ Validation failures for missing required log_specifics fields")
    print("   ❌ Validation failures for non-standardized field values")
    print("   🔧 All functions now have optional parameters with empty string defaults")
    print("   🛡️ Comprehensive validation prevents crashes while providing helpful error messages")

if __name__ == "__main__":
    main()