#!/usr/bin/env python3
"""
Production-Ready Security Logging Examples

This file demonstrates proper usage of all 14 security logging functions
with realistic production data and proper error handling.

Usage:
    python3 example_publish.py

Note: This uses production initialization (no test mode) and will attempt
to publish to the actual SNS topic if AWS credentials are configured.
"""

import sys
import os
from concurrent.futures import ThreadPoolExecutor

# Import the security logging module
import security_logging_sns as SecurityLogging
from security_log_fields import *

def setup_error_handler():
    """Set up custom error handler for fire-and-forget logging failures."""
    def security_logging_error_handler(error_msg, event_type):
        print(f"🚨 Security logging failed for {event_type}: {error_msg}", file=sys.stderr)
        # In production, you would emit CloudWatch metrics here:
        # cloudwatch.put_metric_data(
        #     Namespace='SecurityLogging',
        #     MetricData=[{
        #         'MetricName': 'log_failure',
        #         'Value': 1.0,
        #         'Unit': 'Count',
        #         'Dimensions': [
        #             {'Name': 'ServiceName', 'Value': os.environ.get('SERVICE_NAME', 'example-service')},
        #             {'Name': 'Environment', 'Value': os.environ.get('ENV_TYPE', 'dev')},
        #             {'Name': 'EventType', 'Value': event_type or 'unknown'}
        #         ]
        #     }]
        # )
    
    SecurityLogging.set_security_logging_error_handler(security_logging_error_handler)

def example_authentication_events():
    """Examples of authentication and session logging."""
    print("🔐 Authentication & Session Events")
    
    # 1. Successful User Login
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_login,
            event_type=EventType.LOGIN_SUCCESS,
            actor_identifier="alice@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-abc-123",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            user_role=UserRole.ADMIN,
            status=Status.SUCCESS,
            source_ip_address="192.168.1.100",
            detail="First time login from new device"
        )
        SecurityLogging.fire_and_forget(future, EventType.LOGIN_SUCCESS)
    
    # 2. Failed User Login
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_login,
            event_type=EventType.LOGIN_FAILURE,
            actor_identifier="attacker@external.com",
            actor_type=ActorType.HUMAN_CUSTOMER,
            session_id="session-failed-456",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            user_agent="curl/7.68.0",
            user_role=UserRole.CUSTOMER_USER,
            status=Status.FAILURE,
            source_ip_address="203.0.113.42",
            detail=Detail.INVALID_CREDENTIALS
        )
        SecurityLogging.fire_and_forget(future, EventType.LOGIN_FAILURE)
    
    # 3. MFA Challenge Success
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_mfa_challenge,
            event_type=EventType.MFA_CHALLENGE,
            actor_identifier="bob@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-mfa-789",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
            user_role=UserRole.SALES_REP,
            status=Status.SUCCESS,
            mfa_type=MfaType.TOTP,
            source_ip_address="10.0.1.25",
            detail="MFA verification successful"
        )
        SecurityLogging.fire_and_forget(future, EventType.MFA_CHALLENGE)
    
    # 4. User Logout
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_logout,
            event_type=EventType.USER_LOGOUT,
            actor_identifier="alice@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-abc-123",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            user_role=UserRole.ADMIN,
            status=Status.SUCCESS,
            source_ip_address="192.168.1.100",
            detail=Detail.USER_INITIATED
        )
        SecurityLogging.fire_and_forget(future, EventType.USER_LOGOUT)

def example_authorization_events():
    """Examples of authorization and access control logging."""
    print("🛡️ Authorization & Access Events")
    
    # 5. Permission/Role Change
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_permission_role_change,
            event_type=EventType.PERMISSION_CHANGE,
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-admin-001",
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_user_identifier="newuser@company.com",
            object_changed="Role",
            previous_value="customer_support",
            new_value="admin",
            source_ip_address="10.0.1.30",
            detail="Promoted to admin role for project leadership"
        )
        SecurityLogging.fire_and_forget(future, EventType.PERMISSION_CHANGE)
    
    # 6. User Status Change
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_status_change,
            event_type=EventType.USER_STATUS_CHANGE,
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-admin-002",
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_user_identifier="suspended@company.com",
            detail=Detail.USER_DISABLED,
            source_ip_address="10.0.1.30"
        )
        SecurityLogging.fire_and_forget(future, EventType.USER_STATUS_CHANGE)
    
    # 7. Impersonation Event
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_impersonation_event,
            event_type=EventType.IMPERSONATION_EVENT,
            actor_identifier="support@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-support-003",
            cloud_env_type=CloudEnvType.PROD,
            service_name="customer-support",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_user_identifier="customer@example.com",
            detail=Detail.IMPERSONATION_START,
            source_ip_address="10.0.2.15"
        )
        SecurityLogging.fire_and_forget(future, EventType.IMPERSONATION_EVENT)
    
    # 8. User Invite Event
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_invite_event,
            event_type=EventType.USER_INVITE_EVENT,
            actor_identifier="hr@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-hr-004",
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_user_email="newhire@company.com",
            assigned_role="developer",
            invite_status=InviteStatus.SENT,
            source_ip_address="10.0.1.40",
            detail="New employee onboarding"
        )
        SecurityLogging.fire_and_forget(future, EventType.USER_INVITE_EVENT)

def example_api_access_events():
    """Examples of API endpoint access logging."""
    print("🌐 API Endpoint Access Events")
    
    # 9. API Request Success
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_api_request,
            event_type=EventType.API_REQUEST_PROCESSED,
            actor_identifier="api-client-xyz",
            actor_type=ActorType.SERVICE_PARTNER,
            session_id="api-session-001",
            cloud_env_type=CloudEnvType.PROD,
            service_name="api-gateway",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            auth_protocol=AuthProtocol.API_KEY,
            endpoint_path="/api/v1/customers",
            http_method=HttpMethod.GET,
            authorization_status=Status.SUCCESS,
            endpoint_sensitivity=EndpointSensitivity.CONFIDENTIAL,
            source_ip_address="203.0.113.54",
            detail="Successful customer data retrieval"
        )
        SecurityLogging.fire_and_forget(future, EventType.API_REQUEST_PROCESSED)

def example_data_access_events():
    """Examples of customer data access logging."""
    print("📊 Customer Data Access Events")
    
    # 10. Record Access - Multiple Records (bulk export)
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_record_access,
            event_type=EventType.RECORD_ACCESS,
            actor_identifier="analyst@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-analyst-001",
            cloud_env_type=CloudEnvType.PROD,
            service_name="data-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            endpoint_path="/api/v1/customers/bulk-export",
            data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
            id_list=["cust-001", "cust-002", "cust-003", "cust-004"],
            detail=Detail.EXPORT_REPORT,
            source_ip_address="192.168.2.100"
        )
        SecurityLogging.fire_and_forget(future, EventType.RECORD_ACCESS)
    
    # 11. Record Access - Single Record
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_record_access,
            event_type=EventType.RECORD_ACCESS,
            actor_identifier="support@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-support-002",
            cloud_env_type=CloudEnvType.PROD,
            service_name="customer-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            endpoint_path="/api/v1/customers/customer-12345",
            data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
            id_list=["customer-12345"],  # Single record - just one ID in the list
            fields_accessed=["name", "email", "phone", "address"],
            detail=Detail.VIEW_RECORD,
            source_ip_address="10.0.2.20"
        )
        SecurityLogging.fire_and_forget(future, EventType.RECORD_ACCESS)

def example_configuration_events():
    """Examples of key configuration change logging."""
    print("🔧 Key Configuration Change Events")
    
    # 12. MFA Status Change
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_mfa_status_change,
            event_type=EventType.MFA_STATUS_CHANGE,
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-user-001",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_object="user@company.com",
            status=Status.SUCCESS,
            mfa_id="mfa-device-abc123",
            detail=Detail.MFA_ENABLED,
            source_ip_address="192.168.1.50"
        )
        SecurityLogging.fire_and_forget(future, EventType.MFA_STATUS_CHANGE)
    
    # 13. Password Change/Reset
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_password_change_reset,
            event_type=EventType.PASSWORD_CHANGE_RESET,
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-user-002",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_object="user@company.com",
            status=Status.SUCCESS,
            detail=Detail.PASSWORD_CHANGE,
            source_ip_address="192.168.1.50"
        )
        SecurityLogging.fire_and_forget(future, EventType.PASSWORD_CHANGE_RESET)
    
    # 14. API Key Lifecycle
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_api_key_lifecycle,
            event_type=EventType.API_KEY_LIFECYCLE,
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-admin-003",
            cloud_env_type=CloudEnvType.PROD,
            service_name="api-management",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_object="api-key-xyz789",
            status=Status.SUCCESS,
            detail=Detail.API_KEY_CREATED,
            source_ip_address="10.0.1.60"
        )
        SecurityLogging.fire_and_forget(future, EventType.API_KEY_LIFECYCLE)
    
    # 15. Auth Mechanism Modification
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_auth_mechanism_modification,
            event_type=EventType.AUTH_MECHANISM_MODIFICATION,
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-admin-004",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-config",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="lambda-execution-role",
            target_object="sso_configuration",
            status=Status.SUCCESS,
            detail=Detail.NEW_SSO_PROVIDER,
            source_ip_address="10.0.1.60"
        )
        SecurityLogging.fire_and_forget(future, EventType.AUTH_MECHANISM_MODIFICATION)

def main():
    """Main function demonstrating production-ready security logging."""
    print("🚀 Production-Ready Security Logging Examples")
    print("=" * 60)
    
    # Initialize security logging (production mode)
    try:
        SecurityLogging.init_security_logging()
        print("✅ Security logging initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize security logging: {e}")
        return 1
    
    # Set up error handler for fire-and-forget logging
    setup_error_handler()
    print("✅ Error handler configured for fire-and-forget logging")
    print()
    
    # Run all examples
    example_authentication_events()
    example_authorization_events()
    example_api_access_events()
    example_data_access_events()
    example_configuration_events()
    
    print()
    print("🎉 All security logging examples completed!")
    print("📊 Check your SNS topic and SIEM for the logged events")
    print()
    print("💡 Pro Tips:")
    print("  - All examples use fire_and_forget() to prevent blocking")
    print("  - Error handler will catch and report any failures")
    print("  - Use module-level imports: import sr_sec_py_sns_logger as SecurityLogging")
    print("  - Always use constants from security_log_fields for standardized values")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
