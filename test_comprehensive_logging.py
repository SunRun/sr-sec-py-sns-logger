#!/usr/bin/env python3
"""
Comprehensive Security Logging Test Suite

This script tests all 16 security event types by sending real logs to an SNS topic.
It validates the complete logging functionality including:

- Authentication & Session Events (4 types)
- Authorization & Access Events (4 types) 
- API Endpoint Access Events (2 types)
- Customer Data Action Events (2 types)
- Key Configuration Change Events (4 types)

Usage:
    python3 test_comprehensive_logging.py

The script runs in two phases:
1. Basic connectivity test (5 events) - validates SNS access
2. Comprehensive test suite (16 events) - tests all event types

Configure the SNS topic ARN and region in the initialize_logging() function.
"""

import security_logging_sns
from security_log_fields import (
    Status, ActorType, LogCategory, EventType, AuthProtocol, Detail, MfaType,
    HttpMethod, CloudEnvType, CloudServiceApiType, DataSensitivityLevel,
    EndpointSensitivity, InviteStatus, UserRole
)

def initialize_logging():
    """Initialize security logging with the specified SNS topic."""
    topic_arn = "arn:aws:sns:us-west-2:687126124183:sr-sec-logging-log-topic-dev"
    region = "us-west-2"
    
    print(f"🚀 Initializing security logging for PRODUCTION...")
    print(f"📍 SNS Topic: {topic_arn}")
    print(f"🌍 Region: {region}")
    print("⚠️  This will send real logs to SNS!")
    print("=" * 60)
    
    security_logging_sns.init_security_logging(
        topic_arn=topic_arn,
        region_name=region,
        test_mode=False  # Production mode - actually send to SNS
    )

def test_single_event_per_category():
    """Test one event from each category to verify SNS connectivity."""
    print("\n🧪 Testing One Event Per Category (Production)")
    print("-" * 50)
    
    # Base log details
    base_details = {
        "actor_identifier": "test.automation@sunrun.com",
        "actor_type": ActorType.SYSTEM_SELF,
        "session_id": "test_session_prod_001",
        "cloud_env_type": CloudEnvType.DEV,
        "service_name": "security-logging-test",
        "cloud_env_unique_id": "687126124183",
        "cloud_env_name": "sr-dev-test-environment",
        "service_account_id": "test-automation@sr-dev.iam.gserviceaccount.com",
        "source_ip_address": "10.0.0.1",
        "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
    }
    
    # Test 1: Authentication Event
    print("1. Testing authentication event (login success)...")
    result = security_logging_sns.log_user_login(
        **base_details,
        event_type=EventType.LOGIN_SUCCESS,
        status=Status.SUCCESS,
        user_agent="Security-Logger-Test/1.0",
        user_role=UserRole.ADMIN,
        detail="Automated test login event",
        device_id="test_device_001"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
        return False
    
    # Test 2: Authorization Event
    print("2. Testing authorization event (permission change)...")
    result = security_logging_sns.log_permission_role_change(
        **base_details,
        event_type=EventType.PERMISSION_CHANGE,
        target_user_identifier="test.target@sunrun.com",
        object_changed="TestRole",
        previous_value="User",
        new_value="Admin",
        detail="Automated test permission change"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
        return False
    
    # Test 3: API Endpoint Event
    print("3. Testing API endpoint event...")
    result = security_logging_sns.log_api_request(
        **base_details,
        event_type=EventType.API_REQUEST_PROCESSED,
        auth_protocol=AuthProtocol.API_KEY,
        endpoint_path="/api/v1/test/endpoint",
        http_method=HttpMethod.GET,
        authorization_status=Status.SUCCESS,
        endpoint_sensitivity=EndpointSensitivity.INTERNAL,
        detail="Automated test API request"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
        return False
    
    # Test 4: Customer Data Event
    print("4. Testing customer data event...")
    result = security_logging_sns.log_single_record_access(
        **base_details,
        event_type=EventType.SINGLE_RECORD_ACCESS,
        customer_id="test_customer_001",
        fields_accessed=["test_field_1", "test_field_2"],
        detail=Detail.VIEW_RECORD
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
        return False
    
    # Test 5: Key Configuration Event
    print("5. Testing key configuration event...")
    result = security_logging_sns.log_mfa_status_change(
        **base_details,
        event_type=EventType.MFA_STATUS_CHANGE,
        target_object="test_mfa_config_001",
        status=Status.SUCCESS,
        mfa_id="test_mfa_device_001",
        detail=Detail.MFA_ENABLED
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
        return False
    
    return True

def run_comprehensive_tests():
    """Run comprehensive tests for all event types."""
    print("\n🚀 Running Comprehensive Production Tests")
    print("-" * 50)
    
    try:
        test_authentication_events()
        test_authorization_events()
        test_api_endpoint_events()
        test_customer_data_events()
        test_key_config_events()
        return True
    except Exception as e:
        print(f"❌ Error during comprehensive testing: {str(e)}")
        return False

def test_authentication_events():
    """Test all authentication and session events."""
    print("\n🔐 Testing Authentication & Session Events")
    print("-" * 50)
    
    # Base log details for auth events
    base_details = {
        "actor_identifier": "test.user@company.com",
        "actor_type": ActorType.HUMAN_INTERNAL,
        "session_id": "sess_auth_12345",
        "cloud_env_type": CloudEnvType.DEV,
        "service_name": "auth-service",
        "cloud_env_unique_id": "687126124183",
        "cloud_env_name": "sr-dev-environment",
        "service_account_id": "sa-auth@sr-dev.iam.gserviceaccount.com",
        "source_ip_address": "192.168.1.100",
        "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
    }
    
    # Test 1: Successful Login
    print("1. Testing successful user login...")
    result = security_logging_sns.log_user_login(
        **base_details,
        event_type=EventType.LOGIN_SUCCESS,
        status=Status.SUCCESS,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        user_role=UserRole.ADMIN,
        detail="First time login from new device",
        device_id="device_12345"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 2: Failed Login
    print("2. Testing failed user login...")
    failed_login_details = base_details.copy()
    failed_login_details["actor_identifier"] = "attacker@malicious.com"
    failed_login_details["actor_type"] = ActorType.HUMAN_CUSTOMER
    result = security_logging_sns.log_user_login(
        **failed_login_details,
        event_type=EventType.LOGIN_FAILURE,
        status=Status.FAILURE,
        user_agent="curl/7.68.0",
        user_role=UserRole.CUSTOMER_USER,
        detail=Detail.INVALID_CREDENTIALS,
        device_id="unknown_device"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 3: MFA Challenge
    print("3. Testing MFA challenge...")
    result = security_logging_sns.log_mfa_challenge(
        **base_details,
        event_type=EventType.MFA_CHALLENGE,
        status=Status.SUCCESS,
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
        user_role=UserRole.SALES_REP,
        mfa_type=MfaType.TOTP,
        detail="TOTP verification successful",
        device_id="iphone_67890"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 4: User Logout
    print("4. Testing user logout...")
    result = security_logging_sns.log_user_logout(
        **base_details,
        event_type=EventType.USER_LOGOUT,
        status=Status.SUCCESS,
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        user_role=UserRole.CUSTOMER_SUPPORT,
        detail=Detail.USER_INITIATED,
        device_id="macbook_11111"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")

def test_authorization_events():
    """Test all authorization and access events."""
    print("\n🔑 Testing Authorization & Access Events")
    print("-" * 50)
    
    base_details = {
        "actor_identifier": "admin@company.com",
        "actor_type": ActorType.HUMAN_INTERNAL,
        "session_id": "sess_admin_67890",
        "cloud_env_type": CloudEnvType.DEV,
        "service_name": "user-management",
        "cloud_env_unique_id": "687126124183",
        "cloud_env_name": "sr-dev-environment",
        "service_account_id": "sa-mgmt@sr-dev.iam.gserviceaccount.com",
        "source_ip_address": "10.0.1.50",
        "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
    }
    
    # Test 1: Permission/Role Change
    print("1. Testing permission change...")
    result = security_logging_sns.log_permission_role_change(
        **base_details,
        event_type=EventType.PERMISSION_CHANGE,
        target_user_identifier="user123@company.com",
        object_changed="Role",
        previous_value="Customer Support",
        new_value="Admin",
        detail="Promoted due to team restructuring"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 2: User Status Change
    print("2. Testing user status change...")
    result = security_logging_sns.log_user_status_change(
        **base_details,
        event_type=EventType.USER_STATUS_CHANGE,
        target_user_identifier="suspended.user@company.com",
        detail=Detail.USER_DISABLED
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 3: Impersonation Event
    print("3. Testing impersonation start...")
    result = security_logging_sns.log_impersonation_event(
        **base_details,
        event_type=EventType.IMPERSONATION_EVENT,
        target_user_identifier="customer@external.com",
        detail=Detail.IMPERSONATION_START
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 4: User Invite Event
    print("4. Testing user invite...")
    result = security_logging_sns.log_user_invite_event(
        **base_details,
        event_type=EventType.USER_INVITE_EVENT,
        target_user_email="newuser@company.com",
        assigned_role="Developer",
        invite_status=InviteStatus.SENT,
        detail="New team member onboarding"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")

def test_api_endpoint_events():
    """Test API endpoint access events."""
    print("\n🌐 Testing API Endpoint Access Events")
    print("-" * 50)
    
    base_details = {
        "actor_identifier": "api-client-xyz789",
        "actor_type": ActorType.SERVICE_INTERNAL,
        "session_id": "api-sess-999",
        "cloud_env_type": CloudEnvType.DEV,
        "service_name": "api-gateway",
        "cloud_env_unique_id": "687126124183",
        "cloud_env_name": "sr-dev-environment",
        "service_account_id": "sa-api@sr-dev.iam.gserviceaccount.com",
        "source_ip_address": "10.0.2.100",
        "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
    }
    
    # Test 1: Successful API Request
    print("1. Testing successful API request...")
    result = security_logging_sns.log_api_request(
        **base_details,
        event_type=EventType.API_REQUEST_PROCESSED,
        auth_protocol=AuthProtocol.OAUTH2_JWT,
        endpoint_path="/api/v1/customers/profile",
        http_method=HttpMethod.GET,
        authorization_status=Status.SUCCESS,
        endpoint_sensitivity=EndpointSensitivity.PII_BASIC,
        detail="Customer profile retrieval"
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 2: Failed API Request
    print("2. Testing failed API request...")
    failed_api_details = base_details.copy()
    failed_api_details["actor_identifier"] = "unauthorized-client"
    failed_api_details["actor_type"] = ActorType.SERVICE_CUSTOMER
    result = security_logging_sns.log_api_request(
        **failed_api_details,
        event_type=EventType.API_REQUEST_PROCESSED,
        auth_protocol=AuthProtocol.API_KEY,
        endpoint_path="/api/v1/admin/users",
        http_method=HttpMethod.POST,
        authorization_status=Status.FAILURE,
        endpoint_sensitivity=EndpointSensitivity.SYSTEM_ADMIN,
        detail=Detail.TOKEN_EXPIRED
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")

def test_customer_data_events():
    """Test customer data action events."""
    print("\n📊 Testing Customer Data Action Events")
    print("-" * 50)
    
    base_details = {
        "actor_identifier": "data.analyst@company.com",
        "actor_type": ActorType.HUMAN_INTERNAL,
        "session_id": "sess_data_555",
        "cloud_env_type": CloudEnvType.DEV,
        "service_name": "data-service",
        "cloud_env_unique_id": "687126124183",
        "cloud_env_name": "sr-dev-environment",
        "service_account_id": "sa-data@sr-dev.iam.gserviceaccount.com",
        "source_ip_address": "10.0.3.75",
        "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
    }
    
    # Test 1: Multi-Record Access
    print("1. Testing multi-record access...")
    result = security_logging_sns.log_multi_record_access(
        **base_details,
        event_type=EventType.MULTI_RECORD_ACCESS,
        endpoint_path="/api/v1/customers/export",
        data_sensitivity_level="Confidential-PII",
        record_count=150,
        customer_id_list=["cust_001", "cust_002", "cust_003", "cust_004", "cust_005"],
        detail=Detail.EXPORT_REPORT
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 2: Single Record Access
    print("2. Testing single record access...")
    result = security_logging_sns.log_single_record_access(
        **base_details,
        event_type=EventType.SINGLE_RECORD_ACCESS,
        customer_id="cust_12345",
        fields_accessed=["email", "phone", "address", "payment_method"],
        detail=Detail.VIEW_RECORD
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")

def test_key_config_events():
    """Test key configuration change events."""
    print("\n🔧 Testing Key Configuration Change Events")
    print("-" * 50)
    
    base_details = {
        "actor_identifier": "security.admin@company.com",
        "actor_type": ActorType.HUMAN_INTERNAL,
        "session_id": "sess_security_777",
        "cloud_env_type": CloudEnvType.DEV,
        "service_name": "security-service",
        "cloud_env_unique_id": "687126124183",
        "cloud_env_name": "sr-dev-environment",
        "service_account_id": "sa-security@sr-dev.iam.gserviceaccount.com",
        "source_ip_address": "10.0.4.25",
        "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
    }
    
    # Test 1: MFA Status Change
    print("1. Testing MFA status change...")
    result = security_logging_sns.log_mfa_status_change(
        **base_details,
        event_type=EventType.MFA_STATUS_CHANGE,
        target_object="user_mfa_12345",
        status=Status.SUCCESS,
        mfa_id="mfa_device_67890",
        detail=Detail.MFA_ENABLED
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 2: Password Change/Reset
    print("2. Testing password change...")
    result = security_logging_sns.log_password_change_reset(
        **base_details,
        event_type=EventType.PASSWORD_CHANGE_RESET,
        target_object="user_pwd_54321",
        status=Status.SUCCESS,
        detail=Detail.PASSWORD_CHANGE
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 3: API Key Lifecycle
    print("3. Testing API key lifecycle...")
    result = security_logging_sns.log_api_key_lifecycle(
        **base_details,
        event_type=EventType.API_KEY_LIFECYCLE,
        target_object="api_key_abc123",
        status=Status.SUCCESS,
        detail=Detail.API_KEY_CREATED
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")
    
    # Test 4: Auth Mechanism Modification
    print("4. Testing auth mechanism modification...")
    result = security_logging_sns.log_auth_mechanism_modification(
        **base_details,
        event_type=EventType.AUTH_MECHANISM_MODIFICATION,
        target_object="sso_config_main",
        status=Status.SUCCESS,
        detail=Detail.NEW_SSO_PROVIDER
    )
    print(f"   Result: {result['status']}")
    if result['status'] == 'failure':
        print(f"   Error: {result['message']}")

def main():
    """Main function to run production tests."""
    print("🧪 Security Logging Production Test Suite")
    print("=" * 60)
    
    try:
        # Initialize logging in production mode
        initialize_logging()
        
        # First, test one event per category to verify basic connectivity
        print("\n📋 Phase 1: Basic Connectivity Test")
        if not test_single_event_per_category():
            print("\n❌ Basic connectivity test failed. Stopping here.")
            print("Please check AWS permissions and SNS topic configuration.")
            return 1
        
        print("\n✅ Basic connectivity test passed!")
        
        # Ask user if they want to proceed with comprehensive tests
        response = input("\n🤔 Would you like to run comprehensive tests (all 16 event types)? (y/N): ")
        if response.lower() in ['y', 'yes']:
            print("\n📋 Phase 2: Comprehensive Test Suite")
            if run_comprehensive_tests():
                print("\n🎉 All comprehensive tests completed successfully!")
            else:
                print("\n⚠️ Some comprehensive tests failed, but basic connectivity works.")
        else:
            print("\n👍 Stopping after basic tests as requested.")
        
        print("\n✅ Production testing completed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error during production testing: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
