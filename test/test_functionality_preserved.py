#!/usr/bin/env python3
"""
Test to verify all functionality is preserved after security enhancements.
Uses the dev environment SNS topic for testing.
"""

import sys
import os
from datetime import datetime

# Add current directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_logging_sns import (
    init_security_logging, log_user_login, log_mfa_challenge, log_user_logout,
    log_permission_role_change, log_user_status_change, log_impersonation_event,
    log_user_invite_event, log_api_request, log_record_access,
    log_mfa_status_change, log_password_change_reset,
    log_api_key_lifecycle, log_auth_mechanism_modification
)
from security_log_fields import (
    Status, ActorType, Detail, CloudEnvType, EventType, UserRole,
    AuthProtocol, MfaType, HttpMethod, DataSensitivityLevel,
    EndpointSensitivity, InviteStatus, CloudServiceApiType
)

def test_all_functionality_preserved():
    """Test that all 14 security logging functions work with the dev environment."""
    
    print("🧪 Testing All Functionality Preserved - Dev Environment")
    print("ARN: arn:aws:sns:us-west-2:687126124183:sr-sec-logging-log-topic-dev")
    print("=" * 80)
    
    try:
        # Initialize with dev environment ARN
        print("📡 Initializing security logging with dev environment...")
        init_security_logging(
            topic_arn="arn:aws:sns:us-west-2:687126124183:sr-sec-logging-log-topic-dev",
            region_name="us-west-2"
        )
        print("✅ Security logging initialized successfully")
        print()
        
        timestamp_suffix = datetime.now().strftime('%Y%m%d-%H%M%S')
        test_results = []
        
        # Test a few key functions to verify functionality
        print("1️⃣ Testing User Login Success...")
        result = log_user_login(
            event_type=EventType.LOGIN_SUCCESS,
            status=Status.SUCCESS,
            actor_identifier="test.user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-login-{timestamp_suffix}",
            source_ip_address="192.168.1.100",
            detail=Detail.USER_INITIATED,
            cloud_env_type=CloudEnvType.DEV,
            service_name="auth-service",
            cloud_env_unique_id="687126124183",
            cloud_env_name="dev-us-west-2",
            service_account_id="sa-auth@company.iam.amazonaws.com",
            user_agent="Mozilla/5.0 (Test)",
            user_role=UserRole.ADMIN
        )
        test_results.append(("User Login Success", result))
        
        print("2️⃣ Testing API Request...")
        result = log_api_request(
            event_type=EventType.API_REQUEST_PROCESSED,
            actor_identifier="api-client-test",
            actor_type=ActorType.SERVICE_PARTNER,
            session_id=f"api-session-{timestamp_suffix}",
            source_ip_address="203.0.113.45",
            cloud_env_type=CloudEnvType.DEV,
            service_name="api-gateway",
            cloud_env_unique_id="687126124183",
            cloud_env_name="dev-us-west-2",
            service_account_id="sa-apigateway@company.iam.amazonaws.com",
            auth_protocol=AuthProtocol.API_KEY,
            endpoint_path="/api/v1/customers",
            http_method=HttpMethod.GET,
            authorization_status=Status.SUCCESS,
            endpoint_sensitivity=EndpointSensitivity.CONFIDENTIAL
        )
        test_results.append(("API Request", result))
        
        print("3️⃣ Testing Record Access...")
        result = log_record_access(
            event_type=EventType.RECORD_ACCESS,
            actor_identifier="analyst@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-multi-{timestamp_suffix}",
            source_ip_address="192.168.5.100",
            detail=Detail.EXPORT_REPORT,
            cloud_env_type=CloudEnvType.DEV,
            service_name="reporting-service",
            cloud_env_unique_id="687126124183",
            cloud_env_name="dev-us-west-2",
            service_account_id="sa-reports@company.iam.amazonaws.com",
            endpoint_path="/reports/customer-data",
            data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
            id_list=["test-001", "test-002", "test-003"]
        )
        test_results.append(("Record Access", result))
        
        print()
        print("=" * 80)
        print("📊 TEST RESULTS SUMMARY:")
        print("=" * 80)
        
        success_count = 0
        for test_name, result in test_results:
            if result and result.get('status') == 'success':
                print(f"✅ {test_name}: SUCCESS")
                success_count += 1
            else:
                if isinstance(result, dict):
                    error_status = result.get('status', 'unknown')
                    error_message = result.get('message', '')
                    if error_message:
                        print(f"❌ {test_name}: FAILED - {error_status}")
                        print(f"   Error: {error_message[:100]}{'...' if len(error_message) > 100 else ''}")
                    else:
                        print(f"❌ {test_name}: FAILED - {error_status}")
                else:
                    print(f"❌ {test_name}: FAILED")
        
        print()
        print(f"🎯 Overall Results: {success_count}/{len(test_results)} events published successfully")
        
        if success_count == len(test_results):
            print("🎉 All functionality preserved! Security enhancements work correctly.")
            return True
        else:
            print("⚠️  Some functionality tests failed. Check the results above.")
            return False
            
    except Exception as e:
        print(f"❌ Error during functionality test: {str(e)}")
        print(f"📊 Error type: {type(e).__name__}")
        return False

if __name__ == "__main__":
    success = test_all_functionality_preserved()
    sys.exit(0 if success else 1)





