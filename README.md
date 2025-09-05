# sr-sec-py-sns-logger
This Python module provides a client library for sending structured security logs to a centralized AWS SNS Topic. It is designed to be consumed by other applications to ensure all security events are consistently formatted and delivered to the central security logging pipeline.

This library does not use the standard Python logging module. Instead, it directly publishes JSON messages to a predefined SNS topic using the AWS SDK for Python (boto3), which is more efficient and reliable for this specific security pipeline.

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

## 📚 API Reference

### Initialization
**`init_security_logging(topic_arn=None, region_name=None)`**
Initialize the security logging module. Must be called once before using any logging functions.
- `topic_arn` (optional): SNS Topic ARN. If None, reads from `SECURITY_LOGS_TOPIC_ARN` env var
- `region_name` (optional): AWS region. If None, reads from `AWS_REGION` env var or uses AWS default

### Logging Functions
All logging functions require `base_log_details` as the first argument, followed by event-specific parameters.

**Return Format**: All logging functions return a dictionary with the following structure:
- `{"status": "success"}` - When logging succeeds
- `{"status": "failure", "message": "error details"}` - When logging fails (includes error message)

The functions are designed to never crash your application - they will always return a status dictionary even if there are internal errors.

`log_user_login(...)`
Logs user login success or failure events.

* Parameters: `status`, `session_id`, `user_identifier`, `user_type`, `source_ip_address`, `user_agent`, `user_role`, `device_id` (optional), `context` (optional), `reason` (optional).
* Example Usage:
```
log_user_login(sns_publisher, base_log_details, status=AuthorizationStatus.FAILURE, ...)
```

`log_mfa_challenge(...)`
Logs MFA challenge events.

* Parameters: `status`, `session_id`, `user_identifier`, `user_type`, `source_ip_address`, `user_agent`, `user_role`, `mfa_type`, `device_id` (optional), `reason` (optional).

`log_user_logout(...)`
Logs user logout events.

* Parameters: `session_id`, `user_identifier`, `user_type`, `source_ip_address`, `user_agent`, `reason`.

`log_permission_change(...)`
Logs changes to a user's permissions or roles.

Parameters: `actor_user_identifier`, `target_user_identifier`, `session_id`, `object_changed`, `previous_value`, `new_value`.

`log_user_status_change(...)`
Logs changes to a user's status (e.g., enabled, disabled, deleted).

* Parameters: `actor_user_identifier`, `target_user_identifier`, `action_type`, `actor_user_type`, `reason` (optional).

`log_impersonation_event(...)`
Logs impersonation start or stop events.

* Parameters: `actor_user_identifier`, `actor_session_id`, `target_user_identifier`, `action_type`, `actor_user_type`.

`log_api_request_processed(...)`
Logs details of a processed API request.

* Parameters: `source_ip_address`, `auth_protocol`, `client_id`, `client_type`, `endpoint_path`, `http_method`, `authorization_status`, `endpoint_sensitivity`, `session_id` (optional), `reason` (optional).

`log_multi_record_access(...)`
Logs access to multiple records (e.g., list views, data exports).

* Parameters: `user_identifier`, `source_ip_address`, `action_type`, `record_count`, `session_id`, `actor_user_type`, `endpoint_path` (optional), `data_sensitivity_level` (optional).

`log_single_record_access(...)`
Logs access to a single data record (e.g., view or edit).

* Parameters: `user_identifier`, `source_ip_address`, `customer_id`, `action_type`, `fields_accessed`, `session_id`, `actor_user_type`.

`log_key_configuration_change(...)`
Logs changes to critical configurations like MFA, passwords, or API keys.

* Parameters: `actor_user_identifier`, `actor_session_id`, `target_object`, `change_type`, `status`, `actor_user_type`, `mfa_id` (optional).

⚙️ How it Works
The library uses a clean separation of concerns with the SNSPublisher class handling SNS operations and the logging functions handling event construction. When a logging function is called, it constructs a complete JSON object from the provided parameters and uses the SNSPublisher to publish it to the configured SNS topic with exponential backoff for resilience. This ensures that every log event is a single, structured message ready to be consumed by the downstream pipeline (SNS → Kinesis Firehose → S3).

**Architecture**:
- `sns_publisher.py` - Contains the SNSPublisher class with exponential backoff logic
- `security_logging_sns.py` - Contains logging functions and event construction logic
- `security_log_fields.py` - Contains standardized field definitions

**Error Handling**: All functions include comprehensive try/catch blocks to ensure that logging failures never crash your application. Instead, they return a structured response indicating success or failure with details.

**Production Configuration**: The SNSPublisher includes comprehensive boto3 configuration for production use:
- **Retries**: AWS SDK's built-in retry with exponential backoff (5 attempts total)
- **Timeouts**: Connection timeout (10s) and read timeout (30s) to prevent hanging
- **Connection Pool**: Up to 50 connections for high-throughput scenarios
- **Security**: AWS Signature Version 4 for secure authentication
- **User Agent**: Custom identifier for debugging and monitoring
- **Region**: Configurable AWS region with fallback to default resolution