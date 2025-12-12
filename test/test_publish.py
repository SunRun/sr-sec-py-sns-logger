#!/usr/bin/env python3
"""
Test script and implementation reference for security logging functions.
This script tests all 14 available security event logging functions and serves as
a comprehensive reference for proper implementation patterns.

Features:
- Tests SNS publishing to production topic
- Demonstrates proper field usage with realistic data
- Shows required vs optional field patterns
- Validates all security event types work correctly
- Serves as implementation reference for developers

Run: python3 test_publish.py
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

def test_all_security_events():
    """Test and demonstrate usage of all 14 security logging functions."""
    
    print("🧪 Testing All Security Event Types - Implementation Reference")
    print("ARN: arn:aws:sns:us-west-2:000576341507:sr-sec-logging-log-topic-prod")
    print("=" * 80)
    
    try:
        # Initialize with the new default ARN
        print("📡 Initializing security logging...")
        init_security_logging()
        print("✅ Security logging initialized successfully")
        print()
        
        timestamp_suffix = datetime.now().strftime('%Y%m%d-%H%M%S')
        test_results = []
        
        # 1. User Login Success
        print("1️⃣ Testing User Login Success...")
        result = log_user_login(
            event_type=EventType.LOGIN_SUCCESS,
            status=Status.SUCCESS,
            actor_identifier="john.doe@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-login-{timestamp_suffix}",
            source_ip_address="192.168.1.100",
            detail=Detail.USER_INITIATED,
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-auth@company.iam.amazonaws.com",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            user_role=UserRole.ADMIN
        )
        test_results.append(("User Login Success", result))
        
        # 2. MFA Challenge
        print("2️⃣ Testing MFA Challenge...")
        result = log_mfa_challenge(
            event_type=EventType.MFA_CHALLENGE,
            status=Status.SUCCESS,
            actor_identifier="jane.smith@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-mfa-{timestamp_suffix}",
            source_ip_address="10.0.1.50",
            detail=Detail.USER_INITIATED,
            cloud_env_type=CloudEnvType.PROD,
            service_name="mfa-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-mfa@company.iam.amazonaws.com",
            mfa_type=MfaType.TOTP,
            user_agent="Chrome/91.0.4472.124",
            user_role=UserRole.SALES_REP
        )
        test_results.append(("MFA Challenge", result))
        
        # 3. User Logout
        print("3️⃣ Testing User Logout...")
        result = log_user_logout(
            event_type=EventType.USER_LOGOUT,
            status=Status.SUCCESS,
            actor_identifier="bob.wilson@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-logout-{timestamp_suffix}",
            source_ip_address="172.16.0.25",
            detail=Detail.SESSION_TIMEOUT,
            cloud_env_type=CloudEnvType.PROD,
            service_name="session-manager",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-session@company.iam.amazonaws.com",
            user_agent="Safari/14.1.1",
            user_role=UserRole.CUSTOMER_SUPPORT
        )
        test_results.append(("User Logout", result))
        
        # 4. Permission/Role Change
        print("4️⃣ Testing Permission/Role Change...")
        result = log_permission_role_change(
            event_type=EventType.PERMISSION_CHANGE,
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-perm-{timestamp_suffix}",
            source_ip_address="192.168.1.10",
            detail=Detail.ADMIN_INITIATED,
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-usermgmt@company.iam.amazonaws.com",
            target_user_identifier="alice@company.com",
            object_changed="Role",
            previous_value="Sales Rep",
            new_value="Sales Manager"
        )
        test_results.append(("Permission Change", result))
        
        # 5. User Status Change
        print("5️⃣ Testing User Status Change...")
        result = log_user_status_change(
            event_type=EventType.USER_STATUS_CHANGE,
            actor_identifier="hr-admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-status-{timestamp_suffix}",
            source_ip_address="10.0.2.15",
            detail=Detail.USER_DISABLED,
            cloud_env_type=CloudEnvType.PROD,
            service_name="hr-system",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-hr@company.iam.amazonaws.com",
            target_user_identifier="departed@company.com"
        )
        test_results.append(("User Status Change", result))
        
        # 6. API Request
        print("6️⃣ Testing API Request...")
        result = log_api_request(
            event_type=EventType.API_REQUEST_PROCESSED,
            actor_identifier="api-client-123",
            actor_type=ActorType.SERVICE_PARTNER,
            session_id=f"api-session-{timestamp_suffix}",
            source_ip_address="203.0.113.45",
            cloud_env_type=CloudEnvType.PROD,
            service_name="api-gateway",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-apigateway@company.iam.amazonaws.com",
            auth_protocol=AuthProtocol.API_KEY,
            endpoint_path="/api/v1/customers",
            http_method=HttpMethod.GET,
            authorization_status=Status.SUCCESS,
            endpoint_sensitivity=EndpointSensitivity.PII_BASIC
        )
        test_results.append(("API Request", result))
        
        # 7. Record Access (Multiple Records)
        print("7️⃣ Testing Record Access (Multiple Records)...")
        result = log_record_access(
            event_type=EventType.RECORD_ACCESS,
            actor_identifier="analyst@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-multi-{timestamp_suffix}",
            source_ip_address="192.168.5.100",
            detail=Detail.EXPORT_REPORT,
            cloud_env_type=CloudEnvType.PROD,
            service_name="reporting-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-reports@company.iam.amazonaws.com",
            endpoint_path="/reports/customer-data",
            data_sensitivity_level=DataSensitivityLevel.PII_BASIC,
            id_list=["cust-001", "cust-002", "cust-003"]
        )
        test_results.append(("Record Access (Multiple)", result))
        
        # 8. MFA Status Change
        print("8️⃣ Testing MFA Status Change...")
        result = log_mfa_status_change(
            event_type=EventType.MFA_STATUS_CHANGE,
            actor_identifier="security-admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-mfa-change-{timestamp_suffix}",
            source_ip_address="10.0.1.20",
            cloud_env_type=CloudEnvType.PROD,
            service_name="security-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-security@company.iam.amazonaws.com",
            target_object="newuser@company.com",
            status=Status.SUCCESS,
            mfa_id="mfa-device-123",
            detail=Detail.MFA_ENABLED
        )
        test_results.append(("MFA Status Change", result))
        
        # 9. API Key Lifecycle
        print("9️⃣ Testing API Key Lifecycle...")
        result = log_api_key_lifecycle(
            event_type=EventType.API_KEY_LIFECYCLE,
            actor_identifier="devops@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-apikey-{timestamp_suffix}",
            source_ip_address="172.20.0.50",
            cloud_env_type=CloudEnvType.PROD,
            service_name="api-key-manager",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-apikeys@company.iam.amazonaws.com",
            target_object="api-key-prod-2024",
            status=Status.SUCCESS,
            detail=Detail.API_KEY_CREATED
        )
        test_results.append(("API Key Lifecycle", result))
        
        # 10. Impersonation Event
        print("🔟 Testing Impersonation Event...")
        result = log_impersonation_event(
            event_type=EventType.IMPERSONATION_EVENT,
            actor_identifier="support-admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-impersonate-{timestamp_suffix}",
            source_ip_address="10.0.3.15",
            cloud_env_type=CloudEnvType.PROD,
            service_name="support-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-support@company.iam.amazonaws.com",
            target_user_identifier="customer@company.com",
            detail=Detail.IMPERSONATION_START
        )
        test_results.append(("Impersonation Event", result))
        
        # 11. User Invite Event
        print("1️⃣1️⃣ Testing User Invite Event...")
        result = log_user_invite_event(
            event_type=EventType.USER_INVITE_EVENT,
            actor_identifier="hr-manager@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-invite-{timestamp_suffix}",
            source_ip_address="192.168.2.50",
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-usermgmt@company.iam.amazonaws.com",
            target_user_email="newemployee@company.com",
            assigned_role=UserRole.SALES_REP,
            invite_status=InviteStatus.SENT,
            detail=Detail.USER_INITIATED
        )
        test_results.append(("User Invite Event", result))
        
        # 12. Record Access (Single Record)
        print("1️⃣2️⃣ Testing Record Access (Single Record)...")
        result = log_record_access(
            event_type=EventType.RECORD_ACCESS,
            actor_identifier="support@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-single-{timestamp_suffix}",
            source_ip_address="172.16.1.75",
            cloud_env_type=CloudEnvType.PROD,
            service_name="customer-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-customer@company.iam.amazonaws.com",
            endpoint_path="/api/customers/cust-12345",
            data_sensitivity_level=DataSensitivityLevel.PII_BASIC,
            id_list=["cust-12345"],
            fields_accessed=["email", "phone", "address"],
            detail=Detail.VIEW_RECORD
        )
        test_results.append(("Record Access (Single)", result))
        
        # 13. Password Change Reset
        print("1️⃣3️⃣ Testing Password Change Reset...")
        result = log_password_change_reset(
            event_type=EventType.PASSWORD_CHANGE_RESET,
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-password-{timestamp_suffix}",
            source_ip_address="203.0.113.100",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-auth@company.iam.amazonaws.com",
            target_object="user@company.com",
            status=Status.SUCCESS,
            detail=Detail.PASSWORD_CHANGE
        )
        test_results.append(("Password Change Reset", result))
        
        # 14. Auth Mechanism Modification
        print("1️⃣4️⃣ Testing Auth Mechanism Modification...")
        result = log_auth_mechanism_modification(
            event_type=EventType.AUTH_MECHANISM_MODIFICATION,
            actor_identifier="sso-admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=f"session-sso-{timestamp_suffix}",
            source_ip_address="10.0.0.100",
            cloud_env_type=CloudEnvType.PROD,
            service_name="sso-config-service",
            cloud_env_unique_id="000576341507",
            cloud_env_name="prod-us-west-2",
            service_account_id="sa-sso@company.iam.amazonaws.com",
            target_object="okta-integration",
            status=Status.SUCCESS,
            detail=Detail.SSO_CONFIG_CREATED
        )
        test_results.append(("Auth Mechanism Modification", result))
        
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
                # Only log safe, non-sensitive information to avoid clear-text logging of sensitive data
                if isinstance(result, dict):
                    error_status = result.get('status', 'unknown')
                    error_message = result.get('message', '')
                    if error_message:
                        print(f"❌ {test_name}: FAILED - {error_status}: {error_message}")
                    else:
                        print(f"❌ {test_name}: FAILED - {error_status}")
                else:
                    print(f"❌ {test_name}: FAILED")
        
        print()
        print(f"🎯 Overall Results: {success_count}/{len(test_results)} events published successfully")
        
        if success_count == len(test_results):
            print("🎉 All security event types published successfully to the new SNS topic!")
            return True
        else:
            print("⚠️  Some events failed to publish. Check the results above.")
            return False
            
    except Exception as e:
        print(f"❌ Error during variety test: {str(e)}")
        print(f"📊 Error type: {type(e).__name__}")
        return False

if __name__ == "__main__":
    success = test_all_security_events()
    sys.exit(0 if success else 1)
