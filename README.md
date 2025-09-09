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

```
pip install boto3
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

### User Roles (Examples - Replace with Your System's Roles)
- `role.classification.admin`, `role.classification.sales_rep`, `role.classification.customer_support`
- `role.classification.partner_admin`, `role.classification.customer_user`

**Alternative initialization with explicit parameters:**
```python
# Explicitly provide topic ARN and region
security_logging_sns.init_security_logging(
    topic_arn="arn:aws:sns:us-east-1:123456789012:your-security-logs-topic",
    region_name="us-east-1"
)
```

### Step 3: Define Base Log Details
The core logging functions require a base_log_details dictionary. This dictionary contains common attributes that provide essential context for every log event within a single application instance.

```
# In your application's main function, before logging an event
base_log_details = {
    "aws_request_id": context.aws_request_id,
    "function_name": context.function_name,
    "cloud_env_type": os.environ.get("ENV_TYPE", "dev"),
    "service_name": "my-cool-lambda-service",
    "cloud_service_api_type": "aws_lambda",
    "cloud_env_unique_id": context.invoked_function_arn.split(':')[4],
    "cloud_env_name": os.environ.get("ENV_NAME", "dev-env"),
    "service_account_id": os.environ.get("SERVICE_ACCOUNT_ID")
}
```

### Step 4: Use the Logging Functions
Now you can call the predefined logging functions. Simply import what you need and call the functions with your event data.

```python
from security_logging_sns import log_user_login
from security_log_fields import AuthorizationStatus, UserType

# Log a successful user login event - much simpler!
result = log_user_login(
    base_log_details=base_log_details,
    status=AuthorizationStatus.SUCCESS,
    session_id="some-unique-session-id",
    user_identifier="user-123",
    user_type=UserType.INTERNAL,
    source_ip_address="192.168.1.1",
    user_agent="Mozilla/5.0",
    user_role="admin"
)

# Check the result (optional - logging won't crash your app even if SNS fails)
if result["status"] == "failure":
    print(f"Security logging failed: {result.get('message', 'Unknown error')}")
else:
    print("Security event logged successfully")
```

## 📋 **Complete Usage Example**

```python
import security_logging_sns
from security_log_fields import ActorType, CloudEnvType, CloudServiceApiType, UserRole, AuthProtocol, HttpMethod, EndpointSensitivity, DataSensitivityLevel

# Initialize once at application startup
security_logging_sns.init_security_logging()

# Example 1: User login success
result = security_logging_sns.log_user_login(
    # Base log fields
    actor_identifier="alice@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-xyz789",
    cloud_env_type=CloudEnvType.PROD,
    service_name="user-management-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-user-mgmt@project.iam.gserviceaccount.com",
    source_ip_address="192.168.1.100",
    cloud_service_api_type=CloudServiceApiType.AWS_LAMBDA,
    # Event-specific fields
    user_agent="Mozilla/5.0 (compatible)",
    user_role=UserRole.ADMIN,
    detail="1st time login",
    device_id="device-123",
    login_successful=True
)

# Example 2: Single customer record access
result = security_logging_sns.log_single_record_access(
    # Base log fields
    actor_identifier="alice@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-xyz789",
    cloud_env_type=CloudEnvType.PROD,
    service_name="customer-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-customer-api@project.iam.gserviceaccount.com",
    source_ip_address="192.168.1.100",
    # Event-specific fields
    customer_id="customer-12345",
    fields_accessed=["name", "email", "phone"],
    action_type="view"
)

# Example 3: Multi-record customer data access
result = security_logging_sns.log_multi_record_access(
    # Base log fields
    actor_identifier="alice@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-xyz789",
    cloud_env_type=CloudEnvType.PROD,
    service_name="data-export-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-data-export@project.iam.gserviceaccount.com",
    source_ip_address="192.168.1.100",
    # Event-specific fields
    endpoint_path="/api/v1/customers/export",
    data_sensitivity_level=DataSensitivityLevel.PII_BASIC,
    record_count=1500,
    customer_id_list=["cust-001", "cust-002", "cust-003"],
    action_type="export"
)
```

## 📄 **Comprehensive Log Output Examples**

This section shows the exact JSON structure for all security event types that the system can generate. Each example demonstrates the complete message that gets sent to your SNS topic and forwarded to your SIEM.

### User Login Success
```json
{
  "timestamp": "2025-09-09T19:06:12.359032+00:00",
  "event_type": "authn.login.success",
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
  "detail": "1st time login",
  "device_id": "device-123"
}
```

### User Login Failure
```json
{
  "timestamp": "2025-09-09T19:06:12.359049+00:00",
  "event_type": "authn.login.failure",
  "log_category": "authn_n_session",
  "status": "status.general.failure",
  "actor_identifier": "attacker@external.com",
  "actor_type": "actor.human.customer",
  "session_id": "session-def456",
  "cloud_env_type": "prod",
  "service_name": "user-management-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-user-mgmt@project.iam.gserviceaccount.com",
  "source_ip_address": "203.0.113.42",
  "cloud_service_api_type": "aws_lambda",
  "user_agent": "curl/7.68.0",
  "user_role": "role.classification.customer_user",
  "detail": "detail.auth.invalid_credentials"
}
```

### MFA Challenge Success
```json
{
  "timestamp": "2025-09-09T19:06:12.359119+00:00",
  "event_type": "authn.mfa.challenge_success",
  "log_category": "authn_n_session",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "auth-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-auth@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "cloud_service_api_type": "aws_lambda",
  "user_agent": "Mozilla/5.0 (compatible)",
  "user_role": "role.classification.sales_rep",
  "detail": "login with a successful MFA",
  "mfa_type": "okta verify",
  "device_id": "mobile-device-123"
}
```

### API Request Processed
```json
{
  "timestamp": "2025-09-09T19:10:27.091014+00:00",
  "event_type": "api.request.success",
  "log_category": "api_endpoint_access",
  "status": "status.general.success",
  "actor_identifier": "api-client-xyz",
  "actor_type": "actor.api.client",
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
  "detail": "Successful API call"
}
```

### Permission Change
```json
{
  "timestamp": "2025-09-09T19:10:27.091070+00:00",
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
  "new_value": "senior_developer"
}
```

### Impersonation Start
```json
{
  "timestamp": "2025-09-09T19:10:27.091095+00:00",
  "event_type": "authz.impersonation.start",
  "log_category": "authz_n_access",
  "status": "status.general.success",
  "actor_identifier": "support@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-support-123",
  "cloud_env_type": "prod",
  "service_name": "support-portal",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-support@project.iam.gserviceaccount.com",
  "target_user_identifier": "customer@external.com"
}
```

### MFA Configuration Change
```json
{
  "timestamp": "2025-09-09T19:10:27.091120+00:00",
  "event_type": "authn.mfa.status_enabled",
  "log_category": "key_config_changes",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "security-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-security@project.iam.gserviceaccount.com",
  "target_object": "user-alice",
  "mfa_id": "mfa-device-456"
}
```

### Single Customer Record Access
```json
{
  "timestamp": "2025-09-09T19:10:27.091140+00:00",
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
  "customer_id": "customer-12345",
  "fields_accessed": [
    "name",
    "email",
    "phone"
  ]
}
```

### Multi-Record Customer Data Export
```json
{
  "timestamp": "2025-09-09T19:10:27.091043+00:00",
  "event_type": "data.report.export",
  "log_category": "customer_data_actions",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "data-export-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-data-export@project.iam.gserviceaccount.com",
  "source_ip_address": "192.168.1.100",
  "endpoint_path": "/api/v1/customers/bulk-export",
  "data_sensitivity_level": "sensitivity.level.pii_basic",
  "record_count": 250,
  "customer_id_list": [
    "cust-001",
    "cust-002",
    "cust-003"
  ]
}
```

### User Logout
```json
{
  "timestamp": "2025-09-09T19:10:27.091160+00:00",
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
  "user_agent": "Mozilla/5.0 (compatible)",
  "user_role": "developer",
  "detail": "detail.trigger.user_initiated"
}
```

### User Status Change (Disabled)
```json
{
  "timestamp": "2025-09-09T19:10:27.091180+00:00",
  "event_type": "authz.user.status_disabled",
  "log_category": "authz_n_access",
  "status": "status.general.success",
  "actor_identifier": "admin@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-admin-456",
  "cloud_env_type": "prod",
  "service_name": "user-management-api",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-user-mgmt@project.iam.gserviceaccount.com",
  "target_user_identifier": "bob@company.com",
  "detail": "detail.trigger.admin_initiated"
}
```

### User Invite Sent
```json
{
  "timestamp": "2025-09-09T19:10:27.091200+00:00",
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
  "target_user_email": "newuser@company.com",
  "assigned_role": "developer",
  "invite_status": "sent"
}
```

### Password Configuration Change
```json
{
  "timestamp": "2025-09-09T19:10:27.091220+00:00",
  "event_type": "authn.password.change",
  "log_category": "key_config_changes",
  "status": "status.general.success",
  "actor_identifier": "alice@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-xyz789",
  "cloud_env_type": "prod",
  "service_name": "security-service",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "sa-security@project.iam.gserviceaccount.com",
  "target_object": "user-alice"
}
```

### API Key Configuration Change
```json
{
  "timestamp": "2025-09-09T19:10:27.091240+00:00",
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
  "target_object": "api-client-123"
}
```

> **📝 Note**: The examples above show the exact JSON structure for each security event type. All timestamps are in UTC ISO format, and all fields are automatically populated by the logging functions. Your SIEM will receive these structured messages for analysis and alerting.

## 🧪 **Test Mode**

For development and testing, you can run the module in test mode without AWS credentials:

```python
# Initialize in test mode - no AWS setup needed!
security_logging_sns.init_security_logging(test_mode=True)

# Use normally - logs print to console instead of SNS
result = security_logging_sns.log_user_login(...)
# Output: Pretty-printed JSON showing exactly what would be sent to SNS
```

## 📚 API Reference

### Initialization
**`init_security_logging(topic_arn=None, region_name=None, test_mode=False)`**

Initialize the security logging module. Must be called once before using any logging functions.
- `topic_arn` (optional): SNS Topic ARN. If None, reads from `SECURITY_LOGS_TOPIC_ARN` env var
- `region_name` (optional): AWS region. If None, reads from `AWS_REGION` env var or uses AWS default
- `test_mode` (optional): If True, logs are printed to console instead of sent to SNS

### Available Logging Functions

All functions return `{"status": "success"}` or `{"status": "failure", "message": "error details"}` and will never crash your application.

| **Category** | **Function** | **Use Case** |
|---|---|---|
| **Authentication & Session** | `log_user_login()` | User login success/failure events |
| | `log_mfa_challenge()` | MFA challenge events |
| | `log_user_logout()` | User logout events |
| **Authorization & Access** | `log_permission_change()` | Permission/role changes |
| | `log_user_status_change()` | User enable/disable/delete events |
| | `log_impersonation_event()` | Admin impersonation start/stop |
| | `log_user_invite_event()` | User invite sent/accepted/revoked |
| **API Access** | `log_api_request_processed()` | API endpoint access logging |
| **Customer Data** | `log_single_record_access()` | Single customer record access |
| | `log_multi_record_access()` | Multi-record access/export |
| **Configuration** | `log_key_configuration_change()` | MFA, password, API key changes |

### Function Parameters

All functions require:
1. `base_log_details` - Common context for all events
2. Event-specific parameters (see function signatures in code)

**Common Parameters:**
- `user_identifier` - Who performed the action
- `session_id` - User session identifier  
- `source_ip_address` - Source IP address
- `actor_user_type` - Type of user (internal, partner, customer, etc.)

## ⚙️ **How It Works**

The module provides a simple, production-ready interface for security logging:

1. **Initialization**: `init_security_logging()` sets up the SNS publisher with production-grade configuration
2. **Event Construction**: Logging functions build structured JSON with all required security fields
3. **Automatic Fields**: `timestamp` (UTC) and `event_type` are added automatically
4. **Reliable Delivery**: AWS SDK handles retries with exponential backoff (5 attempts)
5. **Error Safety**: All functions return status instead of throwing exceptions

**Module Files**:
- `security_logging_sns.py` - Main module with logging functions
- `sns_publisher.py` - SNS client with production configuration  
- `security_log_fields.py` - Standardized field constants
- `test_logging.py` - Test script with examples

**Production Features**:
- ✅ **AWS SDK Retries**: Built-in exponential backoff (5 attempts)
- ✅ **Timeouts**: Connection (10s) and read (30s) timeouts prevent hanging
- ✅ **Connection Pool**: Up to 50 concurrent connections for high-throughput
- ✅ **Security**: AWS Signature Version 4 authentication
- ✅ **Monitoring**: Custom user agent for CloudTrail identification
- ✅ **Error Handling**: Never crashes your application