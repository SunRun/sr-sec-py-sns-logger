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
```

### Step 2: Import the Library and Initialize the Publisher
At the entry point of your application (e.g., lambda_handler), import the SNSPublisher class and initialize a publisher instance. It's best to do this at a global scope to avoid re-initializing the Boto3 client on every invocation.

```
# File: my_application.py

import os
from security_logging_sns import SNSPublisher

# Initialize the SNS publisher at the global scope for efficiency
SNS_TOPIC_ARN = os.environ.get("SECURITY_LOGS_TOPIC_ARN")
sns_publisher = SNSPublisher(topic_arn=SNS_TOPIC_ARN)

def lambda_handler(event, context):
    # Your application logic starts here
    ...
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
Now you can call the predefined logging functions from security_logging_sns.py. Pass the initialized sns_publisher and the base_log_details dictionary along with the event-specific data.

```
from security_logging_sns import log_user_login, AuthorizationStatus, UserType

# Log a successful user login event
log_user_login(
    sns_publisher=sns_publisher,
    base_log_details=base_log_details,
    status=AuthorizationStatus.SUCCESS,
    session_id="some-unique-session-id",
    user_identifier="user-123",
    user_type=UserType.INTERNAL,
    source_ip_address="192.168.1.1",
    user_agent="Mozilla/5.0",
    user_role="admin"
)
```

## 📚 API Reference
The primary functions are located in security_logging_sns.py. All functions require the sns_publisher and base_log_details as the first two arguments.

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
The library's core is the SNSPublisher class. When a logging function is called, it constructs a complete JSON object from the provided parameters and publishes it to the configured SNS topic. This ensures that every log event is a single, structured message ready to be consumed by the downstream pipeline (SNS → Kinesis Firehose → S3).