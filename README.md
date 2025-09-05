# sr-sec-py-sns-logger

A Python module for sending structured security logs to AWS SNS for centralized security monitoring. This library ensures all security events are consistently formatted and delivered to your security logging pipeline.

**Key Features:**
- 🔒 **Security-First**: Designed specifically for security event logging
- 🚀 **Production-Ready**: Built-in retry logic, timeouts, and error handling  
- ✅ **Compliance**: Covers all High priority security events with required data points
- 🧪 **Test Mode**: Test without AWS credentials for development and validation
- 📦 **Simple API**: One-line initialization, clean function calls

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
from security_log_fields import AuthorizationStatus, UserType, ActionType

# Initialize once at application startup
security_logging_sns.init_security_logging()

# Define base log details (common to all events in this execution)
base_log_details = {
    "service_name": "user-management-api",
    "cloud_service_api_type": "aws_lambda",
    "cloud_env_type": "production",
    "cloud_env_name": "prod-us-east-1",
    "service_account_id": "123456789012",
    "aws_request_id": "req-abc123"
}

# Example 1: User login
result = security_logging_sns.log_user_login(
    base_log_details=base_log_details,
    status=AuthorizationStatus.SUCCESS,
    session_id="session-xyz789",
    user_identifier="alice@company.com",
    user_type=UserType.INTERNAL,
    source_ip_address="192.168.1.100",
    user_agent="Mozilla/5.0 (compatible)",
    user_role="developer"
)

# Example 2: Single customer record access
result = security_logging_sns.log_single_record_access(
    base_log_details=base_log_details,
    user_identifier="alice@company.com",
    source_ip_address="192.168.1.100",
    customer_id="customer-12345",
    action_type=ActionType.VIEWED,
    fields_accessed=["name", "email", "phone"],
    session_id="session-xyz789",
    actor_user_type=UserType.INTERNAL
)

# Example 3: Multi-record customer data access
result = security_logging_sns.log_multi_record_access(
    base_log_details=base_log_details,
    user_identifier="alice@company.com",
    source_ip_address="192.168.1.100",
    action_type=ActionType.EXPORTED,
    record_count=1500,
    session_id="session-xyz789",
    actor_user_type=UserType.INTERNAL,
    customer_id_list=["cust-001", "cust-002", "cust-003"],
    endpoint_path="/api/v1/customers/export",
    data_sensitivity_level="Confidential-PII"
)
```

## 📄 **Log Output Examples**

### Single Customer Record Access
When a user accesses a single customer record, the following JSON is sent to SNS:

```json
{
  "service_name": "user-management-api",
  "cloud_service_api_type": "aws_lambda",
  "cloud_env_type": "production",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "123456789012",
  "aws_request_id": "req-abc123",
  "log_category": "customer_data_actions",
  "event_type": "single_record_access",
  "user_identifier": "alice@company.com",
  "source_ip_address": "192.168.1.100",
  "customer_id": "customer-12345",
  "action_type": "record_viewed",
  "fields_accessed": [
    "name",
    "email", 
    "phone"
  ],
  "session_id": "session-xyz789",
  "actor_user_type": "internal",
  "timestamp": "2025-09-05T18:29:48.624756+00:00"
}
```

### Multi-Record Customer Data Export
When a user exports multiple customer records, the following JSON is sent to SNS:

```json
{
  "service_name": "user-management-api",
  "cloud_service_api_type": "aws_lambda",
  "cloud_env_type": "production",
  "cloud_env_name": "prod-us-east-1",
  "service_account_id": "123456789012",
  "aws_request_id": "req-abc123",
  "log_category": "customer_data_actions",
  "event_type": "multi_record_access",
  "user_identifier": "alice@company.com",
  "source_ip_address": "192.168.1.100",
  "action_type": "exported",
  "record_count": 1500,
  "session_id": "session-xyz789",
  "actor_user_type": "internal",
  "customer_id_list": [
    "cust-001",
    "cust-002",
    "cust-003"
  ],
  "endpoint_path": "/api/v1/customers/export",
  "data_sensitivity_level": "Confidential-PII",
  "timestamp": "2025-09-05T18:29:58.892500+00:00"
}
```

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