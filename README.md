# sr-sec-py-sns-logger

A Python module for sending structured security logs to AWS SNS for centralized security monitoring. This library ensures all security events are consistently formatted and delivered to your security logging pipeline with comprehensive validation.

**Key Features:**
- 🔒 **Security-First**: Designed specifically for security event logging
- 🚀 **Production-Ready**: Built-in retry logic, timeouts, and error handling  
- ✅ **Compliance**: Covers all High priority security events with required data points
- 🧪 **Test Mode**: Test without AWS credentials for development and validation
- 📦 **Simple API**: One-line initialization, clean function calls
- 🛡️ **Crash-Safe**: All parameters optional with validation - never crashes your app
- 📋 **Schema Compliant**: Implements standardized base_log + log_specifics structure

##  📦 Installation
This module is intended to be copied or included as a submodule in your project's repository. There are no external dependencies beyond the standard AWS SDK.

```
# Clone this repository into your project
git submodule add https://github.com/SunRun/sr-sec-py-sns-logger.git
```

## Dependencies
Ensure you have the boto3 library installed in your Python environment.

```bash
pip install boto3
```

## ⚡ Quick Start Guide

### Minimal Example
```python
import security_logging_sns
from security_log_fields import *

# Initialize (one time at app startup)
security_logging_sns.init_security_logging(
    topic_arn="arn:aws:sns:us-east-1:123456789012:security-logs",
    test_mode=True  # Remove for production
)

# Log a user login
result = security_logging_sns.log_user_login(
    event_type=EventType.LOGIN_SUCCESS,
    actor_identifier="user@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-123",
    cloud_env_type=CloudEnvType.PROD,
    service_name="web-app",
    cloud_env_unique_id="123456789012",
    cloud_env_name="production",
    service_account_id="sa-logger@project.iam.gserviceaccount.com",
    user_agent="Mozilla/5.0",
    user_role=UserRole.ADMIN,
    status=Status.SUCCESS,
    detail=Detail.USER_INITIATED
)

print(result)  # {'status': 'success', 'message_content': '...'}
```

### Complete Working Example
```python
#!/usr/bin/env python3
"""
Example: Complete security logging implementation
This shows how to integrate security logging into a real application.
"""

import os
import security_logging_sns
from security_log_fields import *

def initialize_logging():
    """Initialize security logging - call once at app startup."""
    try:
        # Production initialization
        security_logging_sns.init_security_logging(
            topic_arn=os.getenv("SECURITY_LOGS_TOPIC_ARN"),
            region_name=os.getenv("AWS_REGION", "us-east-1")
        )
        print("✅ Security logging initialized")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize security logging: {e}")
        return False

def authenticate_user(username, password, request_info):
    """Example authentication function with security logging."""
    
    # Simulate authentication logic
    if username == "admin@company.com" and password == "correct":
        # Log successful authentication
        result = security_logging_sns.log_user_login(
            event_type=EventType.LOGIN_SUCCESS,
            actor_identifier=username,
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=request_info["session_id"],
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-auth@company.iam.gserviceaccount.com",
            source_ip_address=request_info["client_ip"],
            user_agent=request_info["user_agent"],
            user_role=UserRole.ADMIN,
            status=Status.SUCCESS,
            detail=Detail.USER_INITIATED
        )
        
        if result["status"] == "failure":
            print(f"⚠️  Failed to log successful auth: {result['message']}")
        
        return {"success": True, "user_role": "admin"}
    
    else:
        # Log failed authentication
        result = security_logging_sns.log_user_login(
            event_type=EventType.LOGIN_FAILURE,
            actor_identifier=username,
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id=request_info["session_id"],
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-auth@company.iam.gserviceaccount.com",
            source_ip_address=request_info["client_ip"],
            user_agent=request_info["user_agent"],
            user_role=UserRole.ADMIN,  # Attempted role
            status=Status.FAILURE,
            detail=Detail.INVALID_CREDENTIALS
        )
        
        if result["status"] == "failure":
            print(f"⚠️  Failed to log failed auth: {result['message']}")
        
        return {"success": False, "error": "Invalid credentials"}

def grant_permission(admin_user, target_user, permission):
    """Example permission change with security logging."""
    
    result = security_logging_sns.log_permission_change(
        actor_identifier=admin_user["email"],
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id=admin_user["session_id"],
        cloud_env_type=CloudEnvType.PROD,
        service_name="user-management",
        cloud_env_unique_id="123456789012",
        cloud_env_name="production",
        service_account_id="sa-mgmt@company.iam.gserviceaccount.com",
        target_user_identifier=target_user["email"],
        permission_name=permission,
        change_type="granted",
        detail=Detail.ADMIN_INITIATED
    )
    
    if result["status"] == "failure":
        print(f"⚠️  Failed to log permission change: {result['message']}")
        return False
    
    print(f"✅ Permission '{permission}' granted to {target_user['email']}")
    return True

def main():
    """Example application main function."""
    
    # Initialize logging
    if not initialize_logging():
        return 1
    
    # Simulate request data
    request_info = {
        "session_id": "sess-abc123",
        "client_ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    # Test authentication
    auth_result = authenticate_user("admin@company.com", "correct", request_info)
    
    if auth_result["success"]:
        # Test permission granting
        admin_user = {
            "email": "admin@company.com",
            "session_id": request_info["session_id"]
        }
        target_user = {"email": "user@company.com"}
        
        grant_permission(admin_user, target_user, "read_customer_data")
    
    return 0

if __name__ == "__main__":
    exit(main())
```

## 🚀 Getting Started
### Step 1: Configure Your Environment
The module requires the ARN of the destination SNS topic. Set the following environment variable in your application's deployment environment (e.g., in your Lambda function configuration or a .env file).

```
export SECURITY_LOGS_TOPIC_ARN="arn:aws:sns:REGION:ACCOUNT_ID:your-security-logs-topic"
export AWS_REGION="us-east-1"  # Set to your preferred AWS region
```

### Step 2: Initialize Security Logging
At the entry point of your application (e.g., lambda_handler), initialize the security logging module. This should be done once at application startup.

```python
# File: my_application.py

import os
import security_logging_sns

# Initialize security logging at the global scope for efficiency
# This will automatically read SECURITY_LOGS_TOPIC_ARN and AWS_REGION from environment
security_logging_sns.init_security_logging()

def lambda_handler(event, context):
    # Your application logic starts here
    ...
```

## 📋 Schema Structure

This module implements a standardized two-part logging schema:

### 1. Base Log Schema (base_log)
**Required fields for every log entry:**

| Field Name | Description | Example Value | Required |
|------------|-------------|---------------|----------|
| `timestamp` | Event timestamp in UTC | `"2025-09-08T20:25:51.000Z"` | ✅ (auto-generated if empty) |
| `event_type` | Dot-notation event identifier | `"authn.login.success"`, `"authz.role.assign"` | ✅ |
| `log_category` | High-level event category | `"authn_n_session"` | ✅ |
| `status` | Event outcome | `"status.general.success"` | ✅ |
| `actor_identifier` | Unique actor identifier | `"user@company.com"` | ✅ |
| `actor_type` | Standardized actor type | `"actor.human.internal"` | ✅ |
| `session_id` | Session identifier | `"session-abc-123"` | ✅ |
| `cloud_env_type` | Environment type | `"prod"`, `"stage"`, `"dev"` | ✅ |
| `service_name` | Application/service name | `"elephant_mfe"` | ✅ |
| `cloud_env_unique_id` | Cloud environment ID | `"aws_account_id"` | ✅ |
| `cloud_env_name` | Environment name | `"ai_team"` | ✅ |
| `service_account_id` | Service account ID | `"sa-log-writer@project.iam"` | ✅ |
| `source_ip_address` | Source IP address | `"203.0.113.54"` | ❌ Optional |
| `cloud_service_api_type` | Cloud service type | `"aws_lambda"` | ❌ Optional |

### 2. Event-Specific Fields (log_specifics)
Additional required fields based on the specific event type. The `detail` field provides context and uses standardized values:

#### Authentication & Session Events
| Event Type | Required Fields | Optional Fields | Detail Field Usage |
|------------|----------------|-----------------|-------------------|
| **User Login** (`authn.login.success`, `authn.login.failure`) | `user_agent`, `user_role`, `detail` | `device_id` | Success: "1st time login", "login with a successful MFA"<br>Failure: `detail.auth.invalid_credentials`, `detail.auth.account_locked` |
| **MFA Challenge** (`authn.mfa.challenge_success`, `authn.mfa.challenge_failure`) | `user_agent`, `user_role`, `detail`, `mfa_type` | `device_id` | Success: "login with a successful MFA"<br>Failure: `detail.auth.invalid_mfa_code` |
| **User Logout** (`authn.logout.*`) | `user_agent`, `user_role`, `detail` | `device_id` | `detail.trigger.user_initiated`, `detail.trigger.session_timeout`, `detail.trigger.admin_initiated` |

#### Authorization & Access Events
| Event Type | Required Fields | Detail Field Usage |
|------------|----------------|-------------------|
| **Permission/Role/Group Change** (`authz.permission.*`, `authz.role.*`, `authz.group_membership.*`) | `target_user_identifier`, `object_changed`, `previous_value`, `new_value` | N/A |
| **User Status Change** (`authz.user.status_*`) | `target_user_identifier`, `detail` | `detail.trigger.admin_initiated`, `detail.trigger.system_policy_violation` |
| **Impersonation** (`authz.impersonation.*`) | `target_user_identifier` | N/A |
| **User Invite** (`authz.invite.*`) | `target_user_email`, `assigned_role`, `invite_status` | N/A |

#### API Endpoint Access Events
| Event Type | Required Fields | Detail Field Usage |
|------------|----------------|-------------------|
| **API Request** (`api.request.success`, `api.request.failure`) | `auth_protocol`, `endpoint_path`, `http_method`, `endpoint_sensitivity`, `detail` | Success: "Successful API call"<br>Failure: `detail.auth.token_expired`, `detail.client.invalid_request` |

#### Customer Data Actions Events
| Event Type | Required Fields |
|------------|----------------|
| **Multi-Record Actions** (`data.customer.list.*`, `data.report.*`) | `endpoint_path`, `data_sensitivity_level`, `record_count`, `customer_id_list` |
| **Single-Record Actions** (`data.customer.record.*`) | `customer_id`, `fields_accessed` |

#### Key Configuration Changes Events
| Event Type | Required Fields |
|------------|----------------|
| **MFA Status Change** (`authn.mfa.status_*`, `authn.mfa.device_*`) | `target_object`, `mfa_id` |
| **Password Change/Reset** (`authn.password.*`) | `target_object` |
| **API Key Lifecycle** (`api_key.*`) | `target_object` |
| **Auth Mechanism Modification** (`authn.sso.config_*`, `authn.local_auth.config_*`) | `target_object` |

### 🛡️ Validation & Error Handling

The module provides comprehensive validation:

1. **Crash-Safe**: All function parameters have empty string defaults
2. **Base Field Validation**: Returns failure message if required base_log fields are missing
3. **Event-Specific Validation**: Returns failure message if required log_specifics fields are missing
4. **Never Crashes**: Invalid calls return `{"status": "failure", "message": "..."}` instead of throwing exceptions

**Example validation failure:**
```python
# Missing required fields
result = security_logging_sns.log_user_login(
    actor_identifier="user@company.com"
    # Missing other required fields
)
# Returns: {"status": "failure", "message": "Required base_log fields missing: actor_type, session_id, cloud_env_type, service_name, cloud_env_unique_id, cloud_env_name, service_account_id"}
```

## 🔧 Configuration Options

### Initialization Parameters

```python
security_logging_sns.init_security_logging(
    topic_arn="arn:aws:sns:us-east-1:123456789012:security-logs",  # Required in production
    region_name="us-east-1",           # Optional, defaults to AWS SDK default
    test_mode=False                    # Optional, set True for testing without AWS
)
```

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `topic_arn` | str | Yes* | AWS SNS Topic ARN for security logs | `None` (reads from `SECURITY_LOGS_TOPIC_ARN` env var) |
| `region_name` | str | No | AWS region for SNS client | AWS SDK default resolution |
| `test_mode` | bool | No | Enable test mode (no AWS calls, prints to console) | `False` |

*Required unless `SECURITY_LOGS_TOPIC_ARN` environment variable is set.

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECURITY_LOGS_TOPIC_ARN` | SNS topic ARN (alternative to passing topic_arn parameter) | `arn:aws:sns:us-east-1:123456789012:security-logs` |
| `AWS_REGION` | Default AWS region | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS credentials (if not using IAM roles) | `AKIAIOSFODNN7EXAMPLE` |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials (if not using IAM roles) | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |

### AWS Permissions Required

Your application's IAM role or user needs the following permission:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:REGION:ACCOUNT:your-security-logs-topic"
        }
    ]
}
```

## 📝 Complete Function Examples

Below are working examples for all 14 available functions with their exact parameters and expected outputs.

### Authentication & Session Functions

#### 1. log_user_login - User Login Success
```python
result = security_logging_sns.log_user_login(
    event_type=EventType.LOGIN_SUCCESS,
    actor_identifier="alice@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-xyz789",
    cloud_env_type=CloudEnvType.PROD,
    service_name="user-management-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-user-mgmt@project.iam.gserviceaccount.com",
    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    user_role=UserRole.ADMIN,
    status=Status.SUCCESS,
    source_ip_address="192.168.1.100",
    detail=Detail.USER_INITIATED
)
```
**Generates:** `login_success` event with `detail: "detail.trigger.user_initiated"`

#### 2. log_mfa_challenge - MFA Challenge
```python
result = security_logging_sns.log_mfa_challenge(
    event_type=EventType.MFA_CHALLENGE,
    actor_identifier="bob@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-mfa-456",
    cloud_env_type=CloudEnvType.PROD,
    service_name="auth-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-auth@project.iam.gserviceaccount.com",
    user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)",
    user_role=UserRole.SALES_REP,
    status=Status.SUCCESS,
    mfa_type=MfaType.SMS,
    source_ip_address="203.0.113.25",
    detail=Detail.USER_INITIATED
)
```
**Generates:** `mfa_challenge` event with `detail: "detail.trigger.user_initiated"`

#### 3. log_user_logout - User Logout
```python
result = security_logging_sns.log_user_logout(
    event_type=EventType.USER_LOGOUT,
    actor_identifier="charlie@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-logout-789",
    cloud_env_type=CloudEnvType.PROD,
    service_name="session-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-session@project.iam.gserviceaccount.com",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    user_role=UserRole.CUSTOMER_SUPPORT,
    status=Status.SUCCESS,
    source_ip_address="10.0.1.45",
    detail=Detail.SESSION_TIMEOUT
)
```
**Generates:** `user_logout` event with `detail: "detail.trigger.session_timeout"`

### Authorization & Access Functions

#### 4. log_permission_role_change - Permission/Role Change
```python
result = security_logging_sns.log_permission_role_change(
    event_type=EventType.PERMISSION_CHANGE,
    actor_identifier="admin@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-admin-perm",
    cloud_env_type=CloudEnvType.PROD,
    service_name="user-management-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-user-mgmt@project.iam.gserviceaccount.com",
    target_user_identifier="newuser@company.com",
    object_changed="Role",
    previous_value="Sales Rep",
    new_value="Admin",
    source_ip_address="10.0.1.25"
)
```
**Generates:** `permission_change` event

#### 5. log_user_status_change - User Status Change
```python
result = security_logging_sns.log_user_status_change(
    event_type=EventType.USER_STATUS_CHANGE,
    actor_identifier="admin@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-admin-status",
    cloud_env_type=CloudEnvType.PROD,
    service_name="user-management-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-user-mgmt@project.iam.gserviceaccount.com",
    target_user_identifier="suspended@company.com",
    detail=Detail.USER_DISABLED,
    source_ip_address="10.0.1.25"
)
```
**Generates:** `user_status_change` event with `detail: "detail.action.user_disabled"`

#### 6. log_impersonation_event - User Impersonation
```python
result = security_logging_sns.log_impersonation_event(
    event_type=EventType.IMPERSONATION_EVENT,
    actor_identifier="support@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-support-impersonate",
    cloud_env_type=CloudEnvType.PROD,
    service_name="support-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-support@project.iam.gserviceaccount.com",
    target_user_identifier="customer@company.com",
    detail=Detail.IMPERSONATION_START,
    source_ip_address="10.0.1.30"
)
```
**Generates:** `impersonation_event` event with `detail: "detail.action.impersonation_start"`

#### 7. log_user_invite_event - User Invitation
```python
result = security_logging_sns.log_user_invite_event(
    event_type=EventType.USER_INVITE_EVENT,
    actor_identifier="hr@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-hr-invite",
    cloud_env_type=CloudEnvType.PROD,
    service_name="invite-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-invite@project.iam.gserviceaccount.com",
    target_user_email="newhire@company.com",
    assigned_role=UserRole.SALES_REP,
    invite_status=InviteStatus.SENT,
    source_ip_address="10.0.1.35",
    detail=Detail.ADMIN_INITIATED
)
```
**Generates:** `user_invite_event` event with `detail: "detail.trigger.admin_initiated"`

### API Endpoint Access Functions

#### 8. log_api_request - API Request Processing
```python
result = security_logging_sns.log_api_request(
    event_type=EventType.API_REQUEST_PROCESSED,
    actor_identifier="api_client_123",
    actor_type=ActorType.SERVICE_PARTNER,
    session_id="session-api-456",
    cloud_env_type=CloudEnvType.PROD,
    service_name="api-gateway",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-api@project.iam.gserviceaccount.com",
    auth_protocol=AuthProtocol.API_KEY,
    endpoint_path="/api/v1/customers",
    http_method=HttpMethod.GET,
    authorization_status=Status.SUCCESS,
    endpoint_sensitivity=EndpointSensitivity.CONFIDENTIAL,
    source_ip_address="203.0.113.54"
)
```
**Generates:** `api_request_processed` event

### Customer Data Actions Functions

#### 9. log_multi_record_access - Multiple Records Access
```python
result = security_logging_sns.log_multi_record_access(
    event_type=EventType.MULTI_RECORD_ACCESS,
    actor_identifier="analyst@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-analyst-data",
    cloud_env_type=CloudEnvType.PROD,
    service_name="analytics-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-analytics@project.iam.gserviceaccount.com",
    endpoint_path="/api/v1/customers",
    data_sensitivity_level="Confidential-PII",
    record_count=150,
    customer_id_list=["cust_001", "cust_002", "cust_003"],
    detail=Detail.VIEW_LIST,
    source_ip_address="192.168.1.200"
)
```
**Generates:** `multi_record_access` event with `detail: "detail.action.view_list"`

#### 10. log_single_record_access - Single Record Access
```python
result = security_logging_sns.log_single_record_access(
    event_type=EventType.SINGLE_RECORD_ACCESS,
    actor_identifier="support@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-support-record",
    cloud_env_type=CloudEnvType.PROD,
    service_name="customer-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-customer@project.iam.gserviceaccount.com",
    customer_id="cust_12345",
    fields_accessed=["email", "phone", "address"],
    detail=Detail.VIEW_RECORD,
    source_ip_address="10.0.1.40"
)
```
**Generates:** `single_record_access` event with `detail: "detail.action.view_record"`

### Key Configuration Changes Functions

#### 11. log_mfa_status_change - MFA Configuration Change
```python
result = security_logging_sns.log_mfa_status_change(
    event_type=EventType.MFA_STATUS_CHANGE,
    actor_identifier="admin@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-admin-mfa",
    cloud_env_type=CloudEnvType.PROD,
    service_name="security-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-security@project.iam.gserviceaccount.com",
    target_object="alice@company.com",
    status=Status.SUCCESS,
    mfa_id="mfa-device-123",
    detail=Detail.MFA_ENABLED,
    source_ip_address="10.0.1.50"
)
```
**Generates:** `mfa_status_change` event with `detail: "detail.action.mfa_enabled"`

#### 12. log_password_change_reset - Password Change/Reset
```python
result = security_logging_sns.log_password_change_reset(
    event_type=EventType.PASSWORD_CHANGE_RESET,
    actor_identifier="alice@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-alice-pwd",
    cloud_env_type=CloudEnvType.PROD,
    service_name="auth-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-auth@project.iam.gserviceaccount.com",
    target_object="alice@company.com",
    status=Status.SUCCESS,
    detail=Detail.PASSWORD_CHANGE,
    source_ip_address="192.168.1.100"
)
```
**Generates:** `password_change_reset` event with `detail: "detail.action.password_change"`

#### 13. log_api_key_lifecycle - API Key Management
```python
result = security_logging_sns.log_api_key_lifecycle(
    event_type=EventType.API_KEY_LIFECYCLE,
    actor_identifier="admin@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-admin-api",
    cloud_env_type=CloudEnvType.PROD,
    service_name="api-management",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-api-mgmt@project.iam.gserviceaccount.com",
    target_object="api_key_xyz123",
    status=Status.SUCCESS,
    detail=Detail.API_KEY_CREATED,
    source_ip_address="10.0.1.55"
)
```
**Generates:** `api_key_lifecycle` event with `detail: "detail.api_key.created"`

#### 14. log_auth_mechanism_modification - Authentication Mechanism Changes
```python
result = security_logging_sns.log_auth_mechanism_modification(
    event_type=EventType.AUTH_MECHANISM_MODIFICATION,
    actor_identifier="admin@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-admin-auth",
    cloud_env_type=CloudEnvType.PROD,
    service_name="auth-config-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-auth-config@project.iam.gserviceaccount.com",
    target_object="sso_assertion_url",
    status=Status.SUCCESS,
    detail=Detail.NEW_SSO_PROVIDER,
    source_ip_address="10.0.1.60"
)
```
**Generates:** `auth_mechanism_modification` event with `detail: "detail.action.new_sso_provider"`

## 🔑 Key Changes: Detail Field Approach

**Important:** All functions now use the `detail` field instead of the old `action_type` parameter:

- ✅ **New Approach**: `detail=Detail.USER_DISABLED` → generates `"detail": "detail.action.user_disabled"`
- ❌ **Old Approach**: `action_type="user_disabled"` (no longer supported)

### Common Detail Field Values:
- **Authentication**: `Detail.USER_INITIATED`, `Detail.SESSION_TIMEOUT`, `Detail.INVALID_CREDENTIALS`
- **Actions**: `Detail.USER_DISABLED`, `Detail.IMPERSONATION_START`, `Detail.VIEW_LIST`, `Detail.VIEW_RECORD`
- **Configuration**: `Detail.MFA_ENABLED`, `Detail.PASSWORD_CHANGE`, `Detail.API_KEY_CREATED`, `Detail.NEW_SSO_PROVIDER`

All detail values are automatically formatted as standardized strings (e.g., `Detail.USER_DISABLED` becomes `"detail.action.user_disabled"`).

## 📚 Complete API Reference

### Initialization Function

#### `init_security_logging(topic_arn=None, region_name=None, test_mode=False)`
Initialize the security logging module. **Call this once at application startup.**

**Parameters:**
- `topic_arn` (str, optional): SNS topic ARN
- `region_name` (str, optional): AWS region
- `test_mode` (bool, optional): Enable test mode

**Raises:**
- `ValueError`: If topic_arn is missing in production mode
- `Exception`: If AWS SNS client initialization fails

**Example:**
```python
# Production
security_logging_sns.init_security_logging(
    topic_arn="arn:aws:sns:us-east-1:123456789012:security-logs"
)

# Development/Testing
security_logging_sns.init_security_logging(test_mode=True)
```

### Authentication & Session Functions

#### `log_user_login(...)`
Log user authentication attempts (successful or failed).

**Required Parameters:**
- All base_log parameters
- `event_type` (str): "login_success" or "login_failure" from `EventType` constants
- `status` (str): "status.general.success" or "status.general.failure" from `Status` constants
- `user_agent` (str): Browser/device info
- `user_role` (str): User role from `UserRole` constants

**Optional Parameters:**
- `detail` (str): Context for success/failure (e.g., "1st time login", "invalid_credentials")
- `device_id` (str): Unique device identifier

**Returns:** `dict` with `status` ("success" or "failure") and optional `message`

#### `log_mfa_challenge(...)`
Log MFA challenge events.

**Required Parameters:**
- All base_log parameters
- `event_type` (str): "mfa_challenge" from `EventType` constants
- `status` (str): "status.general.success" or "status.general.failure" from `Status` constants
- `user_agent` (str): Browser/device info
- `user_role` (str): User role from `UserRole` constants
- `mfa_type` (str): MFA method from `MfaType` constants

**Optional Parameters:**
- `detail` (str): Context for success/failure
- `device_id` (str): Unique device identifier

#### `log_user_logout(...)`
Log user logout events.

**Required Parameters:**
- All base_log parameters
- `event_type` (str): "user_logout" from `EventType` constants
- `status` (str): "status.general.success" or "status.general.failure" from `Status` constants
- `user_agent` (str): Browser/device info
- `user_role` (str): User role from `UserRole` constants

**Optional Parameters:**
- `detail` (str): Why the logout occurred (e.g., "timeout", "user_initiated", "concurrent_session")
- `device_id` (str): Unique device identifier

### Authorization & Access Functions

#### `log_permission_change(...)`
Log permission grants/revokes and role assignments.

**Required Parameters:**
- All base_log parameters
- `target_user_identifier` (str): Target user identifier
- `permission_name` (str): Permission or role name
- `change_type` (str): "granted" or "revoked"

#### `log_user_status_change(...)`
Log user account status changes (enabled/disabled/deleted/locked/unlocked).

**Required Parameters:**
- All base_log parameters
- `target_user_identifier` (str): Target user identifier
- `status_change` (str): Status change type

#### `log_impersonation_event(...)`
Log user impersonation start/stop events.

**Required Parameters:**
- All base_log parameters
- `target_user_identifier` (str): User being impersonated

**Optional Parameters:**
- `detail` (str): Additional context for the impersonation event

#### `log_user_invite_event(...)`
Log user invitation events.

**Required Parameters:**
- All base_log parameters
- `target_user_email` (str): Invited user's email
- `assigned_role` (str): Role assigned in invitation
- `invite_status` (str): Status from `InviteStatus` constants

**Optional Parameters:**
- `detail` (str): Additional context for the invite event

### API & Data Access Functions

#### `log_api_request_processed(...)`
Log API endpoint access attempts.

**Required Parameters:**
- All base_log parameters
- `auth_protocol` (str): Authentication protocol from `AuthProtocol` constants
- `endpoint_path` (str): API endpoint path
- `http_method` (str): HTTP method from `HttpMethod` constants
- `endpoint_sensitivity` (str): Sensitivity level from `EndpointSensitivity` constants

**Optional Parameters:**
- `detail` (str): Detail for the API request failure (if applicable)

#### `log_multi_record_access(...)` / `log_single_record_access(...)`
Log customer data access events.

**Required Parameters:**
- All base_log parameters
- `data_type` (str): Type of data accessed
- `access_successful` (bool): Whether access succeeded

### Key Management Functions

#### `log_key_configuration_change(...)`
Log API key lifecycle events.

**Required Parameters:**
- All base_log parameters
- `key_identifier` (str): Key identifier
- `configuration_change_type` (str): Change type ("created", "revoked", "modified")

#### `log_mfa_status_change(...)`
Log MFA configuration changes.

**Required Parameters:**
- All base_log parameters
- `target_user_identifier` (str): Target user
- `mfa_change_type` (str): Change type ("enabled", "disabled", "device_added", "device_removed")

#### `log_password_change_reset(...)`
Log password change/reset events.

**Required Parameters:**
- All base_log parameters
- `target_user_identifier` (str): Target user
- `password_action` (str): Action type ("change" or "reset")

#### `log_api_key_lifecycle(...)`
Log API key management events.

**Required Parameters:**
- All base_log parameters
- `target_object` (str): The API Client ID or key that was affected
- `detail` (str): The lifecycle action ("created", "revoked", "permissions_modified")

#### `log_auth_mechanism_modification(...)`
Log authentication mechanism changes.

**Required Parameters:**
- All base_log parameters
- `target_object` (str): The configuration object that was changed (e.g., "sso_assertion_url", "local_authentication")
- `detail` (str): The modification type ("sso_config_created", "sso_config_modified", "sso_config_deleted", "local_auth_enabled", "local_auth_disabled")

## ⚠️ Error Handling & Troubleshooting

### Return Values
All logging functions return a dictionary with the following structure:

**Success:**
```python
{
    "status": "success",
    "message_content": "{...json log data...}",  # Only in test mode
    "test_mode": True  # Only in test mode
}
```

**Failure:**
```python
{
    "status": "failure",
    "message": "Description of what went wrong"
}
```

### Common Error Messages

#### Initialization Errors
- `"topic_arn must be provided either as parameter or SECURITY_LOGS_TOPIC_ARN environment variable"`
  - **Solution**: Set the SNS topic ARN via parameter or environment variable

- `"Security logging not initialized. Call init_security_logging() first."`
  - **Solution**: Call `init_security_logging()` before using any logging functions

#### Validation Errors
- `"Required base_log fields missing: field1, field2"`
  - **Solution**: Provide all required base_log fields with non-empty values

- `"Required log_specifics fields missing for [function]: field1, field2"`
  - **Solution**: Provide all required event-specific fields

- `"Invalid [field] value 'invalid_value'. Must use standardized values..."`
  - **Solution**: Use values from the appropriate constants in `security_log_fields.py`

#### AWS/SNS Errors
- `"Error publishing security log to SNS after retries: [AWS error]"`
  - **Solution**: Check AWS credentials, permissions, and SNS topic existence

### Best Practices

#### 1. Initialize Once
```python
# ✅ Good - Initialize at application startup
def app_startup():
    security_logging_sns.init_security_logging(...)

# ❌ Bad - Don't initialize on every request
def handle_request():
    security_logging_sns.init_security_logging(...)  # Inefficient
```

#### 2. Handle Failures Gracefully
```python
# ✅ Good - Check result and handle failures
result = security_logging_sns.log_user_login(...)
if result["status"] == "failure":
    # Log to application logs but don't crash
    app_logger.warning(f"Security logging failed: {result['message']}")

# ❌ Bad - Assume success
security_logging_sns.log_user_login(...)  # Ignores failures
```

#### 3. Use Test Mode for Development
```python
# ✅ Good - Use test mode during development
security_logging_sns.init_security_logging(
    test_mode=True  # No AWS calls, prints to console
)

# ✅ Good - Environment-based configuration
security_logging_sns.init_security_logging(
    test_mode=os.getenv("ENVIRONMENT") != "production"
)
```

#### 4. Use Standardized Values
```python
# ✅ Good - Use constants from security_log_fields
from security_log_fields import ActorType, UserRole, Detail

result = security_logging_sns.log_user_login(
    actor_type=ActorType.HUMAN_INTERNAL,
    user_role=UserRole.ADMIN,
    detail=Detail.INVALID_CREDENTIALS
)

# ❌ Bad - Use raw strings (will fail validation)
result = security_logging_sns.log_user_login(
    actor_type="human",  # Invalid
    user_role="admin",   # Invalid
    detail="custom text"   # Should use standardized Detail constants for failures
)
```

#### 5. Provide Meaningful Details
```python
# ✅ Good - Use standardized success context
security_logging_sns.log_user_login(
    event_type=EventType.LOGIN_SUCCESS,
    status=Status.SUCCESS,
    detail=Detail.USER_INITIATED
    # ... other required parameters
)

# ✅ Good - Use standardized failure reasons
security_logging_sns.log_user_login(
    event_type=EventType.LOGIN_FAILURE,
    status=Status.FAILURE,
    detail=Detail.ACCOUNT_LOCKED
    # ... other required parameters
)
```

## 🧪 Testing & Development

The module includes comprehensive unit tests and integration examples for development and validation:

### Run All Tests
```bash
python3 run_tests.py
```

### Run Unit Tests Only
```bash
python3 -m unittest test_security_logging -v
```

### Run Demo/Integration Tests Only
```bash
python3 test_logging.py
```

### Install Testing Dependencies
```bash
pip install -r requirements-test.txt
```

### Run Tests with Coverage (using pytest)
```bash
pytest --cov=security_logging_sns --cov=security_log_fields --cov-report=html
```

### Test Coverage
The unit tests cover:
- ✅ **Validation Functions**: All standardized field validation logic
- ✅ **Logging Functions**: Each logging function with valid/invalid parameters
- ✅ **Error Handling**: Missing fields, invalid values, and exception handling
- ✅ **Timestamp Management**: Auto-generation and custom timestamp preservation
- ✅ **Initialization**: Proper setup and error conditions
- ✅ **Edge Cases**: Empty parameters, whitespace-only values, and publisher failures

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-test.txt

# Run all tests
python3 run_tests.py

# Run tests with coverage
pytest --cov=security_logging_sns --cov-report=html
```

## 🏗️ Module Structure

### Files Overview

| File | Purpose | Key Contents |
|------|---------|--------------|
| `security_logging_sns.py` | Main logging module | All logging functions, validation, base log creation |
| `security_log_fields.py` | Standardized constants | Event types, status values, actor types, etc. |
| `sns_publisher.py` | AWS SNS integration | SNS client, message publishing, retry logic |
| `test_security_logging.py` | Unit tests | Comprehensive test coverage for all functions |
| `test_logging.py` | Integration demo | Working examples and validation demonstrations |
| `run_tests.py` | Test runner | Unified test execution script |

### Dependencies

- **`boto3`**: AWS SDK for Python (SNS publishing)
- **`pytest`**: Testing framework (development only)
- **`pytest-cov`**: Test coverage reporting (development only)

### Python Version Compatibility
- **Minimum**: Python 3.7+
- **Recommended**: Python 3.9+
- **Tested**: Python 3.8, 3.9, 3.10, 3.11

## 📄 Sample Log Outputs

This section shows the exact JSON structure that gets sent to your SNS topic for each security event type. All examples use current standardized values and schema.

### User Login Success
Generated by: `security_logging_sns.log_user_login(..., event_type=EventType.LOGIN_SUCCESS, status=Status.SUCCESS)`
```json
{
  "timestamp": "2025-09-09T23:13:16.691207+00:00",
  "event_type": "login_success",
  "log_category": "authn_n_session",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "user-management-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-user-mgmt@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "cloud_service_api_type": "aws_lambda",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "user_role": "role.classification.admin",
  "detail": "detail.trigger.user_initiated",
  "device_id": "device-123"
}
```

### User Login Failure
Generated by: `security_logging_sns.log_user_login(..., event_type=EventType.LOGIN_FAILURE, status=Status.FAILURE)`
```json
{
  "timestamp": "2025-09-09T23:13:16.691761+00:00",
  "event_type": "login_failure",
  "log_category": "authn_n_session",
  "status": "status.general.failure",
  "actor_identifier": "attacker@external.com",
  "actor_type": "actor.human.customer",
  "session_id": "session-failed-123",
  "cloud_env_type": "prod",
  "service_name": "auth-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "production",
  "service_account_id": "sa-auth@project.iam.gserviceaccount.com",
  "source_ip_address": "203.0.113.42",
  "cloud_service_api_type": "aws_lambda",
  "user_agent": "curl/7.68.0",
  "user_role": "role.classification.customer_user",
  "detail": "detail.auth.invalid_credentials",
  "device_id": ""
}
```

### MFA Challenge Success
Generated by: `security_logging_sns.log_mfa_challenge(..., status=Status.SUCCESS)`
```json
{
  "timestamp": "2025-09-09T20:37:47.561901+00:00",
  "event_type": "authn.mfa.challenge_success",
  "log_category": "authn_n_session",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-mfa-123",
  "cloud_env_type": "prod",
  "service_name": "auth-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-auth@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "cloud_service_api_type": "",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "user_role": "role.classification.admin",
  "detail": "detail.not_applicable",
  "mfa_type": "totp",
  "device_id": ""
}
```

### User Logout
Generated by: `security_logging_sns.log_user_logout(...)`
```json
{
  "timestamp": "2025-09-09T20:38:18.128257+00:00",
  "event_type": "authn.logout.user_initiated",
  "log_category": "authn_n_session",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "user-management-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-user-mgmt@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "cloud_service_api_type": "aws_lambda",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "user_role": "role.classification.admin",
  "detail": "detail.trigger.user_initiated",
  "device_id": ""
}
```

### API Request Success
Generated by: `security_logging_sns.log_api_request_processed(..., status=Status.SUCCESS)`
```json
{
  "timestamp": "2025-09-09T19:39:11.728000+00:00",
  "event_type": "api.request.success",
  "log_category": "api_endpoint_access",
  "status": "status.general.success",
  "actor_identifier": "api-client-xyz",
  "actor_type": "actor.service.internal",
  "session_id": "api-session-789",
  "cloud_env_type": "prod",
  "service_name": "api-gateway",
  "cloud_env_unique_id": "555666777888",
  "cloud_env_name": "production-api",
  "service_account_id": "sa-api@project.iam.gserviceaccount.com",
  "source_ip_address": "10.0.1.50",
  "cloud_service_api_type": "aws_lambda",
  "auth_protocol": "auth.protocol.oauth2.jwt",
  "endpoint_path": "/api/v1/users/profile",
  "http_method": "http.method.GET",
  "endpoint_sensitivity": "sensitivity.level.confidential",
  "detail": "detail.not_applicable"
}
```

### Permission Change (Role Assignment)
Generated by: `security_logging_sns.log_permission_change(...)`
```json
{
  "timestamp": "2025-09-09T19:39:11.729000+00:00",
  "event_type": "authz.role.assign",
  "log_category": "authz_n_access",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-002",
  "cloud_env_type": "prod",
  "service_name": "user-management",
  "cloud_env_unique_id": "999888777666",
  "cloud_env_name": "production-mgmt",
  "service_account_id": "sa-mgmt@project.iam.gserviceaccount.com",
  "target_user_identifier": "alice@company.com",
  "object_changed": "Role",
  "previous_value": "developer",
  "new_value": "senior_developer",
  "detail": "detail.trigger.admin_initiated"
}
```

### User Invite Event
Generated by: `security_logging_sns.log_user_invite_event(...)`
```json
{
  "timestamp": "2025-09-09T19:39:11.730000+00:00",
  "event_type": "authz.invite.sent",
  "log_category": "authz_n_access",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-789",
  "cloud_env_type": "prod",
  "service_name": "user-management-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-user-mgmt@project.iam.gserviceaccount.com",
  "source_ip_address": "",
  "cloud_service_api_type": "",
  "target_user_email": "newuser@company.com",
  "assigned_role": "developer",
  "invite_status": "sent",
  "detail": "detail.trigger.admin_initiated"
}
```

### Single Customer Record Access
Generated by: `security_logging_sns.log_single_record_access(...)`
```json
{
  "timestamp": "2025-09-09T19:39:11.731000+00:00",
  "event_type": "data.customer.record.view",
  "log_category": "customer_data_actions",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "customer-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-customer-api@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "cloud_service_api_type": "aws_lambda",
  "customer_id": "customer-12345",
  "fields_accessed": ["name", "email", "phone"],
  "detail": "detail.not_applicable"
}
```

### API Key Creation
Generated by: `security_logging_sns.log_api_key_lifecycle(..., detail=Detail.API_KEY_CREATED)`
```json
{
  "timestamp": "2025-09-09T19:39:11.732000+00:00",
  "event_type": "api_key.created",
  "log_category": "key_config_changes",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-789",
  "cloud_env_type": "prod",
  "service_name": "api-management",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-api-mgmt@project.iam.gserviceaccount.com",
  "source_ip_address": "",
  "cloud_service_api_type": "",
  "target_object": "api-key-abc123",
  "detail": "detail.api_key.created"
}
```

### User Status Change
Generated by: `security_logging_sns.log_user_status_change(...)`
```json
{
  "timestamp": "2025-09-09T22:55:22.444138+00:00",
  "event_type": "authz.user.status_enabled",
  "log_category": "authz_n_access",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-456",
  "cloud_env_type": "prod",
  "service_name": "user-management",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-user-mgmt@project.iam.gserviceaccount.com",
  "source_ip_address": "10.0.1.100",
  "cloud_service_api_type": "aws_lambda",
  "target_user_identifier": "alice@company.com",
  "detail": "detail.trigger.admin_initiated"
}
```

### Impersonation Event
Generated by: `security_logging_sns.log_impersonation_event(...)`
```json
{
  "timestamp": "2025-09-09T22:55:22.444453+00:00",
  "event_type": "authz.impersonation.start",
  "log_category": "authz_n_access",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-789",
  "cloud_env_type": "prod",
  "service_name": "admin-portal",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-admin@project.iam.gserviceaccount.com",
  "source_ip_address": "10.0.1.200",
  "cloud_service_api_type": "aws_lambda",
  "target_user_identifier": "alice@company.com",
  "detail": "detail.trigger.admin_initiated"
}
```

### Multi-Record Data Access
Generated by: `security_logging_sns.log_multi_record_access(...)`
```json
{
  "timestamp": "2025-09-09T22:55:22.444596+00:00",
  "event_type": "data.report.export",
  "log_category": "customer_data_actions",
  "status": "status.general.success",
  "actor_identifier": "analyst@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-analyst-001",
  "cloud_env_type": "prod",
  "service_name": "data-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-data@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.2.100",
  "cloud_service_api_type": "gke_namespace",
  "endpoint_path": "/api/v1/customers/bulk-export",
  "data_sensitivity_level": "sensitivity.level.pii_basic",
  "record_count": "250",
  "customer_id_list": "['cust-001', 'cust-002', 'cust-003']",
  "detail": "detail.not_applicable"
}
```

### MFA Status Change
Generated by: `security_logging_sns.log_mfa_status_change(...)`
```json
{
  "timestamp": "2025-09-09T22:55:38.929515+00:00",
  "event_type": "authn.mfa.status_enabled",
  "log_category": "key_config_changes",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-security",
  "cloud_env_type": "prod",
  "service_name": "security-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-security@project.iam.gserviceaccount.com",
  "source_ip_address": "10.0.1.50",
  "cloud_service_api_type": "aws_lambda",
  "target_object": "alice@company.com",
  "mfa_id": "mfa-device-123",
  "detail": "detail.trigger.admin_initiated"
}
```

### Password Change
Generated by: `security_logging_sns.log_password_change_reset(...)`
```json
{
  "timestamp": "2025-09-09T22:55:38.929764+00:00",
  "event_type": "authn.password.change",
  "log_category": "key_config_changes",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-alice-pwd",
  "cloud_env_type": "prod",
  "service_name": "auth-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-auth@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "cloud_service_api_type": "aws_lambda",
  "target_object": "alice@company.com",
  "detail": "detail.trigger.user_initiated"
}
```

### Auth Mechanism Modification
Generated by: `security_logging_sns.log_auth_mechanism_modification(...)`
```json
{
  "timestamp": "2025-09-09T22:55:38.929859+00:00",
  "event_type": "authn.sso.config_created",
  "log_category": "key_config_changes",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-config",
  "cloud_env_type": "prod",
  "service_name": "auth-config-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-auth-config@project.iam.gserviceaccount.com",
  "source_ip_address": "10.0.1.25",
  "cloud_service_api_type": "aws_lambda",
  "target_object": "sso_assertion_url",
  "detail": "detail.auth.sso_config_created"
}
```

> **📝 Note**: All timestamps are in UTC ISO format. The exact structure shown above is what gets sent to your SNS topic and forwarded to your SIEM for analysis and alerting.

## 📊 **Standardized Values Reference**

This section provides the complete list of standardized values for all fields to ensure consistency across your security logs.

### Event Types by Category

#### Authentication & Session
- `authn.login.success`, `authn.login.failure`
- `authn.logout.user_initiated`, `authn.logout.session_timeout`, `authn.logout.admin_initiated`
- `authn.mfa.challenge_success`, `authn.mfa.challenge_failure`
- `authn.password.change`, `authn.password.reset`
- `authn.mfa.status_enabled`, `authn.mfa.status_disabled`, `authn.mfa.device_added`, `authn.mfa.device_removed`
- `authn.sso.config_created`, `authn.sso.config_modified`, `authn.sso.config_deleted`
- `authn.local_auth.config_enabled`, `authn.local_auth.config_disabled`

#### Authorization & Access
- `authz.permission.grant`, `authz.permission.revoke`
- `authz.role.assign`, `authz.role.unassign`
- `authz.group_membership.add`, `authz.group_membership.remove`
- `authz.user.status_enabled`, `authz.user.status_disabled`, `authz.user.status_deleted`, `authz.user.status_locked`, `authz.user.status_unlocked`
- `authz.impersonation.start`, `authz.impersonation.stop`
- `authz.invite.sent`, `authz.invite.accepted`, `authz.invite.revoked`, `authz.invite.expired`

#### Customer Data Actions
- `data.customer.record.view`, `data.customer.record.modify`
- `data.customer.list.view`, `data.customer.list.modify`
- `data.report.export`, `data.report.download`

#### API Endpoint Access
- `api.request.success`, `api.request.failure`

#### Key Configuration Changes
- `api_key.created`, `api_key.revoked`, `api_key.permissions_modified`

### Status Values
- `status.general.success`
- `status.general.failure`

### Actor Types
- `actor.human.internal`, `actor.human.partner`, `actor.human.customer`
- `actor.service.internal`, `actor.service.partner`, `actor.service.customer`
- `actor.system.self`

### MFA Types
- `sms`, `totp`, `push`, `email`
- `okta_verify`, `authenticator_app`, `hardware_token`
- `biometric`, `backup_codes`

### Authentication Protocols
- `auth.protocol.api_key`, `auth.protocol.oauth2.jwt`, `auth.protocol.oauth2.client_credentials`
- `auth.protocol.oauth2.authorization_code`, `auth.protocol.oauth2.implicit`, `auth.protocol.oauth2.password_grant`
- `auth.protocol.saml`, `auth.protocol.oidc`, `auth.protocol.session_cookie`
- `auth.protocol.m2m_token`, `auth.protocol.none`

### HTTP Methods
- `http.method.GET`, `http.method.POST`, `http.method.PUT`, `http.method.PATCH`
- `http.method.DELETE`, `http.method.HEAD`, `http.method.OPTIONS`

### Sensitivity Levels (Data & Endpoints)
- `sensitivity.level.public`, `sensitivity.level.internal`, `sensitivity.level.confidential`
- `sensitivity.level.pii_basic`, `sensitivity.level.pii_financial`, `sensitivity.level.pii_health`
- `sensitivity.level.credential_management`, `sensitivity.level.system_admin`, `sensitivity.level.authentication`

### Detail Field Values

The `detail` field provides context for events and uses these standardized values:

#### Authentication & Session - Failure Focus at Login
- `detail.auth.invalid_credentials`, `detail.auth.account_locked`, `detail.auth.ip_restricted`
- `detail.auth.mfa_required`, `detail.auth.policy_violation`, `detail.auth.captcha_failure`
- `detail.auth.token_expired`, `detail.auth.token_invalid`, `detail.auth.unauthorized_access`
- `detail.auth.rate_limit_exceeded`

#### Action/Status Change Triggers (Generic)
- `detail.trigger.user_initiated`, `detail.trigger.admin_initiated`, `detail.trigger.system_automated`
- `detail.trigger.system_policy_violation`, `detail.trigger.session_timeout`, `detail.trigger.concurrent_session`
- `detail.trigger.failed_attempts_threshold`

#### General System/Operational (Generic)
- `detail.system.internal_error`, `detail.system.service_unavailable`, `detail.system.maintenance`
- `detail.client.invalid_request`, `detail.not_applicable`

#### API Key Lifecycle Actions
- `detail.api_key.created`, `detail.api_key.revoked`, `detail.api_key.permissions_modified`

#### Auth Mechanism Modification Types
- `detail.auth.sso_config_created`, `detail.auth.sso_config_modified`, `detail.auth.sso_config_deleted`
- `detail.auth.local_auth_enabled`, `detail.auth.local_auth_disabled`

### User Roles (Examples - Replace with Your System's Roles)
- `role.classification.admin`, `role.classification.sales_rep`, `role.classification.customer_support`
- `role.classification.partner_admin`, `role.classification.customer_user`

---

## 📞 Support & Contact

### Common Issues
1. **Import Errors**: Ensure all files are in the same directory or Python path
2. **AWS Credentials**: Check IAM permissions and credential configuration
3. **Validation Failures**: Use constants from `security_log_fields.py`
4. **Test Failures**: Run `python3 -m pip install -r requirements-test.txt`

### Getting Help
- **Documentation**: This README contains comprehensive usage information
- **Examples**: See `test_logging.py` for working integration examples
- **Unit Tests**: `test_security_logging.py` shows expected behavior for all functions
- **Error Messages**: All validation errors include specific guidance on fixing issues

### Internal Support
For internal support and questions:
- Check this documentation first - it's comprehensive
- Review the unit tests for expected behavior examples
- Run `python3 test_logging.py` to see working integration examples
- Use test mode (`test_mode=True`) for debugging without AWS credentials



*This documentation is comprehensive and designed to enable full understanding and implementation of the security logging module. For additional questions or clarifications, refer to the code comments and unit tests which serve as the definitive specification.*
