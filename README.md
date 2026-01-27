# sr-sec-py-sns-logger: Developer Implementation Guide

A Python module for sending structured security logs to AWS SNS for centralized security monitoring. This guide takes you from initial setup to a fully instrumented, production-ready implementation.

**Key Features:**
- 🔒 **Security-First**: Designed specifically for security event logging
- 🚀 **Production-Ready**: Built-in retry logic, timeouts, and error handling  
- ✅ **Compliance**: Covers all High priority security events with required data points
- 🧪 **Test Mode**: Test without AWS credentials for development and validation
- 📦 **Simple API**: One-line initialization, clean function calls
- 🛡️ **Validation**: Comprehensive validation with detailed error messages showing all missing fields
- 📋 **Schema Compliant**: Implements standardized flat JSON structure with all required security fields
- ⚡ **Non-Blocking**: Fire-and-forget pattern prevents application blocking
- 📊 **Auto-Batching**: Automatically handles large record lists that exceed SNS message limits
- 🔍 **Context Extraction**: Automatically captures function/file name for enhanced debugging

---

## 📑 Table of Contents

### Getting Started
1. [Why Security Logging Matters](#-why-security-logging-matters)

### Part 1: Quick Start (5-Minute Goal)
2. [Install and Setup](#step-1-install-and-setup)
3. [Initialize the Logger](#step-2-initialize-the-logger)
4. [Log Your First Event](#step-3-log-your-first-event)

### Before Production Implementation
5. [The Developer's Mindset](#-the-developers-mindset-guidance-and-principles)
6. [Prerequisites: Review Required](#-prerequisites-review-required)
7. [Request SNS Permissions](#-request-sns-permissions)

### Part 2: The Implementation Playbook
8. [Identify Security-Relevant Activities](#step-1-identify-security-relevant-activities)
9. [Map Activities to Logger Functions](#step-2-map-your-activities-to-logger-events)
10. [Track Your Implementation Progress](#step-3-track-your-implementation-progress)

### Part 3: API Function Reference
11. [Authentication & Session Events](#authentication--session-events)
12. [Authorization & Access Events](#authorization--access-events)
13. [API & Data Access Events](#api--data-access-events)
14. [Key Configuration & Security Changes](#key-configuration--security-changes)

### Part 3.5: Auto-Context Extraction Helpers
15. [Available Context Helpers](#available-context-helpers)
16. [Auto-Extracted Fields](#auto-extracted-fields)
17. [Fields Requiring Manual Input](#fields-requiring-manual-input)
18. [Runtime Failure for Missing Fields](#runtime-failure-for-missing-fields)

### Part 4: Production Readiness
15. [GitHub Actions CI/CD Setup](#github-actions-cicd-setup)
16. [AWS IAM Permissions](#aws-iam-permissions)
17. [REQUIRED: Failure Monitoring](#required-failure-monitoring)
18. [Configuration Options](#configuration-options)

### Appendix
19. [Schema Structure & Fields](#appendix-a-schema-structure--fields)
20. [Sample Log Outputs](#appendix-b-sample-log-outputs)
21. [Migration from TypeScript Version](#appendix-c-migration-from-typescript-version)
22. [Error Handling & Troubleshooting](#appendix-d-error-handling--troubleshooting)
23. [Module Structure](#appendix-e-module-structure)
24. [Python Support](#appendix-f-python-support)
25. [Testing & Development](#appendix-g-testing--development)

---

## 🎯 Why Security Logging Matters

Implementing comprehensive security logging is not just a compliance requirement—it's a critical foundation for mature cybersecurity operations. This package enables organizations to:

**🔍 Mature Risk Detection Methods**
- Build baseline behavior patterns to identify anomalous activities
- Enable advanced threat hunting and security analytics
- Support machine learning-based security detection systems
- Create comprehensive audit trails for forensic investigations

**🛡️ Insider Threat Prevention**  
- Monitor privileged user activities and administrative actions
- Track data access patterns to detect unauthorized behavior
- Identify policy violations and suspicious access attempts
- Enable real-time alerting on high-risk activities

**🏢 Poaching Risk Reduction**
- Log customer data access to prevent unauthorized data harvesting
- Track bulk data exports and multi-record access patterns  
- Monitor user behavior changes that may indicate malicious intent
- Provide evidence for incident response and legal proceedings

Without proper security logging, organizations operate blind to internal threats, compliance violations, and sophisticated attacks that bypass perimeter defenses. This package ensures every critical security event is captured, formatted consistently, and delivered to your security monitoring systems for analysis and response.

---

# Part 1: Quick Start (5-Minute Goal)

This section's goal is to verify your setup and send your first log. We will log a simple user login event to confirm that the pipeline is working correctly.

## Step 1: Install and Setup

### Recommended: Install via Pip from GitHub

The easiest and recommended way to install this package is via pip from GitHub:

```bash
pip install git+https://github.com/SunRun/sr-sec-py-sns-logger.git@master
```

Or add to your `requirements.txt`:

```
sr-sec-py-sns-logger @ git+https://github.com/SunRun/sr-sec-py-sns-logger.git@master
boto3>=1.26.0
```

**Benefits:**
- ✅ Standard Python package management
- ✅ Automatic dependency resolution
- ✅ Easy version updates
- ✅ No manual file copying needed
- ✅ Works seamlessly in CI/CD pipelines

### Alternative: Install as Git Submodule (Legacy)

If you prefer to use git submodules (not recommended for new projects):

```bash
# Add as submodule
git submodule add https://github.com/SunRun/sr-sec-py-sns-logger.git

# Update submodule
git submodule update --init --recursive
```

Then manually copy files or create symlinks in your source directory. **Note:** This approach requires manual management and doesn't integrate well with standard Python tooling.

---

## Step 2: Initialize the Logger

In your application's main entry point (e.g., `app.py`, `main.py`), initialize the logger **once**. 

**⚠️ CRITICAL**: For all development and testing, use `test_mode=True`. This prints logs to the console instead of sending them to the security team's AWS SNS topic.

```python
import sr_sec_py_sns_logger as SecurityLogging

# Initialize once at application startup
SecurityLogging.init_security_logging(test_mode=True)  # Use test_mode for all non-production

print('✅ Security logging initialized.')
```

**Production Configuration:**
```python
# In production with environment config (recommended)
SecurityLogging.init_security_logging(
    cloud_env_type=SecurityLogging.CloudEnvType.PROD,
    cloud_env_unique_id=os.environ.get('AWS_ACCOUNT_ID'),
    cloud_env_name='production',
    service_account_id=os.environ.get('AWS_EXECUTION_ROLE_ARN'),
    service_name='my-application',
)
```

**Benefit**: Once these fields are set during initialization, you don't need to pass them with every log call - they're automatically included!

**Multi-Region Failover Configuration (Optional but Recommended):**

For high availability, you can enable automatic failover to a secondary AWS region:

```python
# With failover enabled (automatically fails over to us-east-2)
SecurityLogging.init_security_logging(
    topic_arn="arn:aws:sns:us-west-2:123456789012:sr-sec-logging-log-topic-dev",
    failover_topic_arn="arn:aws:sns:us-east-2:123456789012:sr-sec-logging-log-topic-failover-dev",
    enable_failover=True  # Default: True
)
```

**How Failover Works:**
- Primary region (us-west-2) is tried first with fast timeout (2 seconds)
- If primary fails with retriable error, automatically switches to failover region (us-east-2)
- Circuit breaker prevents repeated attempts to failing regions
- Automatic recovery when primary region becomes healthy
- Zero code changes required - completely transparent to your application

**Environment Variables (Alternative Configuration):**
```bash
export SECURITY_LOGS_TOPIC_ARN="arn:aws:sns:us-west-2:123456789012:my-topic"
export SECURITY_LOGS_FAILOVER_TOPIC_ARN="arn:aws:sns:us-east-2:123456789012:my-failover-topic"
export AWS_REGION="us-west-2"
export SECURITY_LOGS_FAILOVER_REGION="us-east-2"
```

**IAM User Credentials (For Applications Not Using IAM Roles):**

If your application uses IAM User credentials (static access keys) instead of IAM Roles (Lambda execution roles, ECS task roles, etc.), you can provide credentials directly:

```python
import os
import sr_sec_py_sns_logger as SecurityLogging

# With explicit IAM User credentials
SecurityLogging.init_security_logging(
    aws_access_key_id=os.environ.get('MY_AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('MY_AWS_SECRET_ACCESS_KEY'),
    # aws_session_token=os.environ.get('AWS_SESSION_TOKEN'),  # Optional, for temporary credentials
    test_mode=(os.environ.get('ENV') != 'production'),
)
```

> **Note**: If credentials are not provided, the AWS SDK (boto3) uses the default credential chain (environment variables `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM roles, credential files, etc.)

**Required IAM Policy for IAM Users:**

If using IAM User credentials to publish to a cross-account SNS topic, the IAM User needs this policy attached:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSNSPublishToSecurityLogging",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": [
        "arn:aws:sns:us-west-2:687126124183:sr-sec-logging-log-topic-dev",
        "arn:aws:sns:us-west-2:000576341507:sr-sec-logging-log-topic-prod",
        "arn:aws:sns:us-east-2:000576341507:sr-sec-logging-log-topic-failover-prod"
      ]
    },
    {
      "Sid": "AllowKMSForSNS",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey*", "kms:Decrypt"],
      "Resource": [
        "arn:aws:kms:us-west-2:687126124183:key/*",
        "arn:aws:kms:us-west-2:000576341507:key/*",
        "arn:aws:kms:us-east-2:000576341507:key/*"
      ],
      "Condition": {
        "StringEquals": {
          "kms:ViaService": [
            "sns.us-west-2.amazonaws.com",
            "sns.us-east-2.amazonaws.com"
          ]
        }
      }
    }
  ]
}
```

**Monitoring Failover:**
```python
# Get failover metrics
metrics = SecurityLogging.get_failover_metrics()
print(f"Primary success: {metrics['primary_success']}")
print(f"Failover used: {metrics['failover_success']} times")
print(f"Total failures: {metrics['total_failures']}")

# Reset metrics (useful for periodic monitoring)
SecurityLogging.reset_failover_metrics()
```

---

## Step 3: Log Your First Event

Now that the logger is initialized, it's time to add your first security log. This step will guide you through identifying where to instrument your code and understanding where each value comes from.

### 📍 Step 3a: Locate Your Login Handler

First, identify where user authentication happens in your application. Common locations include:

- **Flask/Django**: Login route handler (e.g., `POST /auth/login`)
- **FastAPI**: Authentication endpoint or dependency
- **AWS Lambda**: Authorization/authentication Lambda functions
- **Other frameworks**: Wherever your application verifies credentials and creates a session

### 📖 Step 3b: Review the log_user_login Function

Before implementing, review the `log_user_login` function definition to understand all available parameters:

👉 **[View log_user_login in security_logging_sns.py](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py)** (Search for "Authentication & Session Events")

This shows you:
- Required vs optional parameters
- Validation rules
- Expected data types
- Available constants

### 💡 Step 3c: Understand Where Values Come From

Before writing code, map out where you'll get each required value:

| Parameter | Where to Find It | Example Source |
|-----------|-----------------|----------------|
| `actor_identifier` | User's email/username from your auth system | `user.email`, `session['user_email']`, decoded JWT `sub` |
| `actor_type` | Type of user logging in | `ActorType.HUMAN_INTERNAL` for employees, `ActorType.HUMAN_CUSTOMER` for customers |
| `session_id` | Session ID from your session management | `session.sid`, `request.session.session_key`, JWT `jti` |
| `user_agent` | HTTP request headers | `request.headers.get('User-Agent')` |
| `user_role` | User's role/permission level | Map your app's roles to `UserRole` constants |
| `cloud_env_unique_id` | AWS Account ID or GCP Project ID | Environment variable, hardcoded per environment |
| `service_account_id` | IAM role/service account running your code | Lambda execution role name, ECS task role, etc. |

**⚠️ Tip**: If you need to decode/extract values (e.g., from a JWT token), do this **before** calling the logging function.

### 📝 Step 3d: Implementation Example

Here's a complete example showing how to integrate security logging into a Flask login route:

```python
import os
import sr_sec_py_sns_logger as SecurityLogging
from security_log_fields import *
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, session

app = Flask(__name__)

# ===== STEP 1: Initialize ONCE at app startup =====
# Environment fields are set here and automatically included in ALL subsequent logs
SecurityLogging.init_security_logging(
    test_mode=(os.environ.get('ENV') != 'production'),
    cloud_env_type=CloudEnvType.PROD,
    cloud_env_unique_id=os.environ.get('AWS_ACCOUNT_ID'),
    cloud_env_name='production',
    service_account_id='ecs-task-role',
    service_name='api-server',
)

# ===== STEP 2: Use in your routes - much simpler! =====
@app.route('/api/login', methods=['POST'])
def login():
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        user = authenticate_user(email, password)
        
        if not user:
            # Log failed login - only event-specific fields needed!
            with ThreadPoolExecutor() as executor:
                future = executor.submit(SecurityLogging.log_user_login,
                    actor_identifier=email,
                    actor_type=ActorType.HUMAN_INTERNAL,
                    session_id=session.sid,
                    event_type=EventType.LOGIN_ATTEMPT,
                    status=Status.FAILURE,
                    user_agent=request.headers.get('User-Agent'),
                    user_role=UserRole.UNKNOWN,
                    auth_protocol=AuthProtocol.FORM_BASED,
                    detail=Detail.INVALID_CREDENTIALS,
                )
                SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
            return {'error': 'Invalid credentials'}, 401
        
        # Log successful login
        with ThreadPoolExecutor() as executor:
            future = executor.submit(SecurityLogging.log_user_login,
                actor_identifier=user.email,
                actor_type=ActorType.HUMAN_INTERNAL,
                session_id=session.sid,
                event_type=EventType.LOGIN_ATTEMPT,
                status=Status.SUCCESS,
                user_agent=request.headers.get('User-Agent'),
                user_role=UserRole.ADMIN if user.role == 'admin' else UserRole.STANDARD_USER,
                auth_protocol=AuthProtocol.FORM_BASED,
                detail=Detail.USER_INITIATED,
            )
            SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
        
        return {'success': True, 'user': user.email}
        
    except Exception as error:
        print(f'Login error: {error}')
        return {'error': 'Server error'}, 500
```

### ✅ Verify It Works

Run your application in development mode (with `test_mode=True`) and trigger a login. You should see the security log printed to your console:

```json
{
  "timestamp": "2025-12-13T04:33:12.100224+00:00",
  "event_type": "login_attempt",
  "log_category": "authn_n_session",
  "status": "status.general.success",
  "actor_identifier": "user@company.com",
  "actor_type": "actor.human.internal",
  "session_id": "session-abc-123",
  "cloud_env_type": "prod",
  "service_name": "api-server",
  "cloud_env_unique_id": "123456789012",
  "cloud_env_name": "production",
  "service_account_id": "ecs-task-role",
  "source_ip_address": "10.0.0.1",
  "user_agent": "Mozilla/5.0...",
  "user_role": "role.classification.admin",
  "auth_protocol": "auth.protocol.form_based",
  "detail": "detail.trigger.user_initiated",
  "event_uuid": "1ade00c0-3dde-4d1f-b39e-eea13a472dd2",
  "caller_function": "login",
  "caller_file": "auth_routes.py"
}
```

**Note:** Fields like `event_uuid`, `caller_function`, and `caller_file` are automatically generated.

**🎉 Congratulations!** You've sent your first security log. The infrastructure is working. Now, let's move on to instrumenting your entire application.

---

# Before Production Implementation

## 🧠 The Developer's Mindset: Guidance and Principles

Implementing this framework requires more than just copying code. As an engineer, you possess the most intricate knowledge of your application. Adopting this standard effectively requires a thoughtful approach.

**Think, Don't Just Apply**: Use these templates as a guide, not a blind script. Question assumptions about your application's logic. For example, how does your service handle different user types or authentication workflows? Your implementation must reflect this context.

**Know Your Endpoints**: You are responsible for understanding the data sensitivity of your application's endpoints. Avoid mislabeling logs by correctly identifying the type and sensitivity of the data being accessed.

**Security is Your Responsibility**: Developers are the primary security implementers. This framework is a tool to help you build more secure applications by providing visibility into critical events.

---

## 📋 Prerequisites: Review Required

**⚠️ MANDATORY REQUIREMENT**: Before implementing any security logging functions, you **MUST** thoroughly review both the standardized field definitions and the organizational logging framework:

#### 🔗 **Required Reading**:
1. **[Introduction to the Sunrun Security Logging Framework](https://docs.google.com/document/d/1nSL0ImYuCG3Alr4_BeUETdHoz1nBrQrhp5jnv55f8cQ/edit?tab=t.0)** - Organizational security logging standards and requirements
2. **[security_log_fields.py](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_log_fields.py)** - Technical field definitions and constants

**Why This Review is Critical:**

1. **🎯 Standardized Values Required**: All security log events MUST use the predefined constants from `security_log_fields.py`. Custom or arbitrary string values will cause validation failures.

2. **📊 Schema Compliance**: The security logging system enforces strict schema validation. Understanding the required fields for each event type speeds up onboarding.

3. **🔍 Audit & Compliance**: Security teams and auditors expect consistent, standardized field values across all applications. Deviating from the standard creates compliance gaps.

4. **🛠️ Implementation Success**: Reviewing the field definitions first will save significant development time by preventing common validation errors.

#### **Key Areas to Review:**

- **Event Types**: Complete list of supported security events (`EventType` class)
- **Actor Types**: Standardized actor classifications (`ActorType` class) 
- **Status Values**: Success/failure indicators (`Status` class)
- **Detail Values**: Contextual information for events (`Detail` class)
- **User Roles**: Role classifications for your organization (`UserRole` class)
- **Required vs Optional Fields**: Understanding which fields are mandatory for each event type

#### **Implementation Workflow:**

1. **📋 Step 1**: Review the [Introduction to the Sunrun Security Logging Framework](https://docs.google.com/document/d/1nSL0ImYuCG3Alr4_BeUETdHoz1nBrQrhp5jnv55f8cQ/edit?tab=t.0) to understand organizational requirements
2. **📖 Step 2**: Review [`security_log_fields.py`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_log_fields.py) for technical field definitions
3. **🎯 Step 3**: Identify the specific event types your application needs to log
4. **✅ Step 4**: Map your application's data to the standardized field values
5. **🔧 Step 5**: Implement security logging using the predefined constants
6. **🧪 Step 6**: Test in `test_mode=True` to validate field usage before production

**❌ Common Mistakes to Avoid:**
- Using raw strings instead of predefined constants (e.g., `"admin"` instead of `UserRole.ADMIN`)
- Skipping required fields for specific event types
- Creating custom detail values instead of using standardized `Detail` constants
- Not importing the constants properly from `security_log_fields.py`

#### Data Sensitivity Levels

When logging record access events, you must specify the sensitivity level of the data being accessed. Use this guide to select the appropriate level:

| Level | Constant | When to Use | Examples |
|-------|----------|-------------|----------|
| **PUBLIC** | `DataSensitivityLevel.PUBLIC` | Data that can be publicly shared | Product catalogs, marketing content, public APIs, help docs |
| **NON_PUBLIC** | `DataSensitivityLevel.NON_PUBLIC` | Internal business data, not customer-specific | Internal reports, aggregated metrics, config settings, team directories |
| **CONFIDENTIAL** | `DataSensitivityLevel.CONFIDENTIAL` | Customer/business data that shouldn't leak | Customer records, agreements, contracts, contact info, pricing |
| **RESTRICTED** | `DataSensitivityLevel.RESTRICTED` | Highly sensitive - PII, credentials, financial | SSN, bank accounts, passwords, API keys, health data |

**Decision Guide:**
```
Is this data publicly available (website, public API)?
  → YES: PUBLIC
  → NO: ↓

Does this data belong to a specific customer or contain PII?
  → YES: Is it highly sensitive (SSN, financial, credentials, health)?
         → YES: RESTRICTED
         → NO: CONFIDENTIAL
  → NO: NON_PUBLIC
```

The same levels apply to `EndpointSensitivity` for API endpoint classification.

### Request SNS Permissions

Before you can use this security logging module in production, you need to request permissions to publish to the security logging SNS topic.

#### Step-by-Step Instructions

1. **Gather Your Information**: Collect the details listed in the Slack template below
2. **Post in Slack**: Send the template message to the security team
3. **Wait for Approval**: The security team will configure the necessary permissions
4. **Test Your Setup**: Use the examples in this guide to verify everything works

#### Slack Request Template

Copy and paste this template into your request:

```
Hi Security Team! 👋

I need SNS topic permissions for security logging in my application.

📋 **Application Details:**
• Application Name: [your-app-name]
• Environment: [dev/staging/prod]
• Team: [your-team-name]
• Slack Channel: #your-team-channel

🔐 **AWS/GCP Details:**
• AWS Account ID / GCP Project ID: [123456789012]
• IAM Role/Service Account: [see examples below based on your infrastructure]
• Region: [us-west-2, us-east-1, etc.]
• SNS Topic Region: us-west-2 (fixed - this is where the security logging SNS topic is located)

📖 **Documentation Review:**
✅ I have reviewed the security logging documentation and implementation guide

**📍 Note About Cross-Region Publishing:**
The security logging SNS topic is located in **us-west-2**, regardless of where your application runs. AWS SNS supports cross-region publishing, so your application can publish to the us-west-2 topic even if it runs in a different region (e.g., Shanghai/ap-southeast-1). No special configuration needed - just ensure your IAM role has permissions to publish to the us-west-2 SNS topic.

🙏 Thank you!
```

#### IAM Role/Service Account Examples by Infrastructure Type

| Infrastructure Type | Example IAM Role/Service Account |
|-------------------|----------------------------------|
| **AWS Lambda** | `arn:aws:iam::123456789012:role/my-lambda-execution-role` |
| **AWS Amplify** | `arn:aws:iam::123456789012:role/amplify-my-app-role` |
| **AWS ECS/Fargate** | `arn:aws:iam::123456789012:role/ecs-task-execution-role` |
| **AWS EC2** | `arn:aws:iam::123456789012:role/ec2-instance-role` |
| **GKE (Google)** | `serviceAccount:my-app@project-id.iam.gserviceaccount.com` |
| **EKS (Kubernetes)** | `arn:aws:iam::123456789012:role/eks-pod-execution-role` |
| **Local/Dev Environment** | `your-aws-profile-name` or `arn:aws:iam::123456789012:user/developer-name` |

### 5-Minute Getting Started

#### Step 1: Install via Pip (Recommended)
```bash
pip install git+https://github.com/SunRun/sr-sec-py-sns-logger.git@master
```

Or add to your `requirements.txt`:
```
sr-sec-py-sns-logger @ git+https://github.com/SunRun/sr-sec-py-sns-logger.git@master
boto3>=1.26.0
```

Then install:
```bash
pip install -r requirements.txt
```

#### Step 2: Quick Example
```python
import sr_sec_py_sns_logger as SecurityLogging
from concurrent.futures import ThreadPoolExecutor

# Initialize (one time at app startup)
SecurityLogging.init_security_logging(
    test_mode=True  # Remove for production
)

# ⚠️ PERFORMANCE NOTE: Direct logging calls can block your application!
# 
# Current config: 30s timeout per attempt × 5 attempts = up to 150 seconds worst-case
# If SNS is slow/down, this WILL delay your user's response.
#
# 🔥 RECOMMENDED: Use fire-and-forget pattern (see below) to avoid blocking while still
# capturing failures in CloudWatch for monitoring/alerting.

# BLOCKING approach (NOT recommended for production):
# result = SecurityLogging.log_user_login(...)

# NON-BLOCKING approach (RECOMMENDED):
# Note: Environment fields (cloud_env_type, service_name, etc.) already set in init_security_logging()
with ThreadPoolExecutor() as executor:
    future = executor.submit(
        SecurityLogging.log_user_login,
        event_type=SecurityLogging.EventType.LOGIN_ATTEMPT,
        actor_identifier="user@company.com",
        actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
        session_id="session-123",
        user_agent="Mozilla/5.0",
        user_role=SecurityLogging.UserRole.ADMIN, # Map your app's roles to library constants
        auth_protocol=SecurityLogging.AuthProtocol.FORM_BASED,  # Username/password, OAuth2, SAML, etc.
        status=SecurityLogging.Status.SUCCESS,
        detail="First time login from new device"
    )
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.LOGIN_ATTEMPT)

# Application continues immediately - not blocked by SNS!
print("✅ Security logging initiated (non-blocking)")
```

#### Step 5: Set Up Error Monitoring
```python
# Set up custom error handler for failures (once at startup)
def security_error_handler(error_msg, event_type):
    print(f"🚨 Security logging failed for {event_type}: {error_msg}")
    # In production, emit CloudWatch metrics here for alerting

SecurityLogging.set_security_logging_error_handler(security_error_handler)
```

**🎉 That's it!** You now have non-blocking security logging with error monitoring. For complete examples of all 14 event types, see [`example_publish.py`](example_publish.py).

---

## 🎯 Best Practice: Fire-and-Forget Pattern

**Problem:** Direct security logging calls can block your application for up to 150 seconds if SNS is slow or unavailable, causing poor user experience.

**Solution:** Use the fire-and-forget pattern to log security events asynchronously without blocking your application.

### Step 1: Set Up Error Handler (Once at Startup)
```python
import sr_sec_py_sns_logger as SecurityLogging
import boto3
import os

def setup_security_logging():
    """Initialize security logging with error handling."""
    # Initialize the module
    SecurityLogging.init_security_logging()
    
    # Set up custom error handler for failures
    def security_error_handler(error_msg, event_type):
        print(f"🚨 Security logging failed for {event_type}: {error_msg}")
        
        # Push failure metric to CloudWatch for alerting
        cloudwatch = boto3.client('cloudwatch')
        cloudwatch.put_metric_data(
            Namespace='SecurityLogging',
            MetricData=[{
                'MetricName': 'log_failure',
                'Value': 1.0,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'ServiceName', 'Value': os.environ.get('SERVICE_NAME', 'unknown')},
                    {'Name': 'Environment', 'Value': os.environ.get('ENV_TYPE', 'unknown')},
                    {'Name': 'EventType', 'Value': event_type or 'unknown'}
                ]
            }]
        )
    
    SecurityLogging.set_security_logging_error_handler(security_error_handler)

# Call once at application startup
setup_security_logging()
```

### Step 2: Use Fire-and-Forget Everywhere
```python
from concurrent.futures import ThreadPoolExecutor

# In your application code - this is NON-BLOCKING
def handle_user_login(user_email, session_id, user_agent):
    # Your application logic here...
    
    # Log security event (non-blocking)
    # Note: Environment fields already set in init_security_logging()
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_login,
            event_type=SecurityLogging.EventType.LOGIN_ATTEMPT,
            actor_identifier=user_email,
            actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
            session_id=session_id,
            user_agent=user_agent,
            user_role=SecurityLogging.UserRole.ADMIN,
            auth_protocol=SecurityLogging.AuthProtocol.FORM_BASED,
            status=SecurityLogging.Status.SUCCESS,
            detail="Successful login"
        )
        SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.LOGIN_ATTEMPT)
    
    # Return response immediately - user not blocked by SNS
    return {"status": "success", "message": "Login successful"}
```

### Step 3: Monitor with CloudWatch Alarms
```hcl
# CloudWatch alarm configuration (Terraform)
resource "aws_cloudwatch_metric_alarm" "security_logging_failures" {
  alarm_name          = "security-logging-failures-prod"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "log_failure"
  namespace           = "SecurityLogging"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "SEV_1: Critical - Security logging failures detected"
  
  dimensions = {
    ServiceName = "your-service-name"
    Environment = "prod"
  }
}
```

### Benefits of Fire-and-Forget Pattern
- ✅ **Non-blocking**: User requests return immediately
- ✅ **Failure monitoring**: Errors are captured and reported via CloudWatch
- ✅ **Reliability**: SNS issues don't impact user experience
- ✅ **Observability**: Failed logs trigger alerts for investigation
- ✅ **Performance**: No impact on application response times

### Comparison: Blocking vs Non-Blocking

| Approach | User Experience | Failure Handling | Performance Impact |
|----------|----------------|------------------|-------------------|
| **Blocking** (`result = log_user_login(...)`) | ❌ Poor (up to 150s delays) | ✅ Immediate feedback | ❌ High (blocks requests) |
| **Fire-and-Forget** (`fire_and_forget(future, event_type)`) | ✅ Excellent (no delays) | ✅ CloudWatch alerting | ✅ None (async) |

---

## 📋 Part 2: The Implementation Playbook

### Step 1: List Your Activities

Before implementing security logging, create a comprehensive list of all security-relevant activities in your application:

**Authentication & Session Activities:**
- User login attempts (success/failure)
- Multi-factor authentication challenges
- User logout events
- Session timeouts

**Authorization & Access Control:**
- Permission/role changes
- User account status changes (disabled, enabled, deleted)
- Administrative impersonation events
- User invitation events

**API & Data Access:**
- API endpoint access (especially sensitive endpoints)
- Customer/entity data viewing/modification
- Bulk data exports or reports
- Record access (single or multiple records)

**Configuration Changes:**
- MFA device management
- Password changes/resets
- API key lifecycle events
- Authentication mechanism modifications

### Step 2: Map Activities to Logger Events

For each activity you identified, determine which security logging function to use. This decision guide will help you choose the right function:

#### **Is the activity about a user logging in, out, or using MFA?**  
📖 **Review the [Authentication & Session functions →](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L221)**
- ➡️ Use: [`log_user_login()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L221) - User successfully/unsuccessfully logs in
- ➡️ Use: [`log_mfa_challenge()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L318) - MFA verification attempt
- ➡️ Use: [`log_user_logout()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L420) - User logs out or session ends

#### **Is the activity about changing permissions, roles, or user status?**
📖 **Review the [Authorization & Access functions →](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L521)**
- ➡️ Use: [`log_permission_role_change()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L521) - Permission/role/group membership changes
- ➡️ Use: [`log_user_status_change()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L615) - User disabled/enabled/deleted
- ➡️ Use: [`log_impersonation_event()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L694) - Admin impersonating another user
- ➡️ Use: [`log_user_invite_event()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L780) - User invitations sent/accepted/revoked

#### **Is the activity about API access or endpoint requests?**
📖 **Review the [API Endpoint Access functions →](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L876)**
- ➡️ Use: [`log_api_request()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L876) - API endpoint access (success/failure)

#### **Is the activity about viewing or modifying customer/entity data?**
📖 **Review the [Customer Data Actions functions →](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L984)**
- ➡️ Use: [`log_record_access()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L984) - Viewing/modifying records (single or multiple - pass 1 or more IDs in `id_list`)

#### **Is the activity about security configuration changes?**
📖 **Review the [Key Configuration Changes functions →](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L1182)**
- ➡️ Use: [`log_mfa_status_change()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L1182) - MFA enabled/disabled/device added
- ➡️ Use: [`log_password_change_reset()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L1274) - Password changes/resets
- ➡️ Use: [`log_api_key_lifecycle()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L1362) - API key created/revoked/modified
- ➡️ Use: [`log_auth_mechanism_modification()`](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_logging_sns.py#L1449) - SSO configuration changes

**💡 Pro Tip:** Click the function links above to see the exact parameters and examples for each function!

### Step 3: Track Implementation Progress

Create a checklist to track your implementation progress:

**✅ Implementation Checklist:**
- [ ] SNS permissions requested and approved
- [ ] Security logging initialized in application startup
- [ ] Error handler configured for fire-and-forget logging
- [ ] CloudWatch monitoring set up with alarms
- [ ] Authentication events implemented
- [ ] Authorization events implemented  
- [ ] API access events implemented
- [ ] Customer data access events implemented
- [ ] Configuration change events implemented
- [ ] All events tested in `test_mode=True`
- [ ] Production deployment with monitoring verified

---

## 📋 Part 3: API Function Reference

### Available Functions
The library provides 13 security logging functions covering:
- **Authentication & Session**: `log_user_login()`, `log_mfa_challenge()`, `log_user_logout()`
- **Authorization & Access**: `log_permission_role_change()`, `log_user_status_change()`, `log_impersonation_event()`, `log_user_invite_event()`
- **API & Data Access**: `log_api_request()`, `log_record_access()` (unified function for single or multiple records)
- **Key Management**: `log_mfa_status_change()`, `log_password_change_reset()`, `log_api_key_lifecycle()`, `log_auth_mechanism_modification()`

### Function Signature Pattern
All functions follow this pattern:
```python
# Fields set ONCE in init_security_logging() - auto-included in all logs:
# cloud_env_type, cloud_env_unique_id, cloud_env_name, service_account_id, service_name

def log_function_name(
    # Per-call parameters (required for all functions)
    actor_identifier="",
    actor_type="", 
    session_id="",
    # Event-specific parameters (vary by function)
    # Optional parameters
    source_ip_address="",
    service_component_name="",  # e.g., "auth-handler", "payment-processor"
):
    return {"status": "success|failure", "message": "..."}
```

### Key Function Examples

#### User Login
```python
with ThreadPoolExecutor() as executor:
    future = executor.submit(
        SecurityLogging.log_user_login,
        event_type=SecurityLogging.EventType.LOGIN_ATTEMPT,
        actor_identifier="alice@company.com",
        actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
        session_id="session-xyz789",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        user_role=SecurityLogging.UserRole.ADMIN,
        auth_protocol=SecurityLogging.AuthProtocol.OAUTH2_JWT,
        status=SecurityLogging.Status.SUCCESS,
        source_ip_address="192.168.1.100",
        detail="First time login from new device"
    )
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.LOGIN_ATTEMPT)
```

#### MFA Challenge (Linked to Login via session_id)
```python
# Example: Complete MFA authentication flow
# Step 1: User enters username/password successfully
with ThreadPoolExecutor() as executor:
    future = executor.submit(
        SecurityLogging.log_user_login,
        event_type=SecurityLogging.EventType.LOGIN_ATTEMPT,
        actor_identifier="alice@company.com",
        actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
        session_id="session-mfa-flow-123",  # Same session_id for linked events
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        user_role=SecurityLogging.UserRole.ADMIN,
        auth_protocol=SecurityLogging.AuthProtocol.FORM_BASED,
        status=SecurityLogging.Status.SUCCESS,  # Password verified
        detail=SecurityLogging.Detail.USER_INITIATED
    )
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.LOGIN_ATTEMPT)

# Step 2: User completes MFA challenge - FAILURE example
with ThreadPoolExecutor() as executor:
    future = executor.submit(
        SecurityLogging.log_mfa_challenge,
        event_type=SecurityLogging.EventType.MFA_CHALLENGE,
        actor_identifier="alice@company.com",
        actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
        session_id="session-mfa-flow-123",  # SAME session_id = linked to login above
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        user_role=SecurityLogging.UserRole.ADMIN,
        mfa_type=SecurityLogging.MfaType.TOTP,
        status=SecurityLogging.Status.FAILURE,  # MFA failed
        detail=SecurityLogging.Detail.MFA_INVALID_CODE  # Specific failure reason
    )
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.MFA_CHALLENGE)

# Query later: SELECT * FROM logs WHERE session_id = 'session-mfa-flow-123'
# Returns: login_attempt (success) + mfa_challenge (failure) = complete auth flow
```

#### API Request
```python
with ThreadPoolExecutor() as executor:
    future = executor.submit(
        SecurityLogging.log_api_request,
        event_type=SecurityLogging.EventType.API_REQUEST_PROCESSED,
        actor_identifier="api_client_123",
        actor_type=SecurityLogging.ActorType.SERVICE_PARTNER,
        session_id="session-api-456",
        auth_protocol=SecurityLogging.AuthProtocol.API_KEY,
        endpoint_path="/api/v1/customers",
        http_method=SecurityLogging.HttpMethod.GET,
        authorization_status=SecurityLogging.Status.SUCCESS,
        endpoint_sensitivity=SecurityLogging.EndpointSensitivity.CONFIDENTIAL,
        source_ip_address="203.0.113.54"
    )
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.API_REQUEST_PROCESSED)
```

#### Permission Change
```python
with ThreadPoolExecutor() as executor:
    future = executor.submit(
        SecurityLogging.log_permission_role_change,
        event_type=SecurityLogging.EventType.PERMISSION_CHANGE,
        actor_identifier="admin@company.com",
        actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
        session_id="session-admin-perm",
        target_user_identifier="newuser@company.com",
        object_changed="Role",
        previous_value="customer_support",
        new_value="admin",
        source_ip_address="10.0.1.25"
    )
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.PERMISSION_CHANGE)
```

> **📝 Note**: For complete examples of all 14 available functions, see [`example_publish.py`](example_publish.py).

---

## 📋 Part 3.5: Auto-Context Extraction Helpers

The package includes helper functions that automatically extract common security context fields from your application request context, reducing boilerplate and ensuring consistency.

### Available Context Helpers

```python
from sr_sec_py_sns_logger import (
    create_security_context,       # Main helper: extracts all available fields
    get_missing_context_fields,    # Check which fields couldn't be auto-extracted
    diagnose_security_context,     # Get detailed info on missing fields + how to fix
    warn_missing_context_fields,   # Log warnings for missing fields (dev helper)
)
```

### Auto-Extracted Fields

| Field | Source (Priority Order) | Notes |
|-------|-------------------------|-------|
| `actor_identifier` | `session['email']` → `session['user']['email']` → `session['attributes']['email']` (Cognito) | From auth session dict |
| `user_agent` | `request.headers['user-agent']` | Works with Flask, FastAPI, Lambda events |
| `source_ip_address` | `x-forwarded-for` → `x-real-ip` → `cf-connecting-ip` → `remote_addr` | Client IP from proxy headers |
| `endpoint_path` | Lambda `rawPath`/`path`, Flask `request.path`, FastAPI `request.url.path` | Request path |
| `http_method` | Lambda `httpMethod`, Flask/FastAPI `request.method` | GET, POST, etc. |
| `session_id` | `session['id']` → `session['session_id']` → `session_token` (hashed) → `jti` (hashed) → `email+expires` (hashed) | Stable throughout user session |
| `cloud_env_type` | `CLOUD_ENV_TYPE` → `NEXT_PUBLIC_ENVIRONMENT_NAME` → `ENVIRONMENT`/`ENV` → `NODE_ENV` → Lambda function name pattern | Auto-mapped to `prod`/`stage`/`dev`/`test` |
| `cloud_env_name` | `CLOUD_ENV_NAME` → `NEXT_PUBLIC_ENVIRONMENT_NAME` → `ENVIRONMENT`/`ENV` → `NODE_ENV` | Human-readable name (formatted) |
| `cloud_env_unique_id` | `CLOUD_ENV_UNIQUE_ID` → `AWS_ACCOUNT_ID` → ARN parsing from `AWS_EXECUTION_ROLE_ARN`, `AWS_LAMBDA_FUNCTION_ARN` | AWS Account ID (12-digit) |
| `service_name` | `SERVICE_NAME` → `NEXT_PUBLIC_APP_NAME` → `AWS_LAMBDA_FUNCTION_NAME` (cleaned) | Application/service name |
| `service_account_id` | `SERVICE_ACCOUNT_ID` → `AWS_EXECUTION_ROLE_ARN` → `AWS_ROLE_ARN` → `ROLE_ARN` → IAM user pattern from `AWS_ACCESS_KEY_ID` | IAM role/user ARN |

**Note:** If you set `cloud_env_type`, `cloud_env_unique_id`, `cloud_env_name`, `service_account_id`, or `service_name` during `init_security_logging()`, those values take precedence and are automatically included in all logs.

### Fields Requiring Manual Input

These fields **must** be set manually and cannot be auto-extracted:

| Field | Why Manual? |
|-------|-------------|
| `actor_type` | Business logic decision (HUMAN_INTERNAL, SYSTEM, etc.) |
| `user_role` | Application-specific role from your database/auth system |
| `event_type` | Specific to the action being performed |
| `status` | Outcome of the operation |
| Other event-specific fields | Depends on the event type |

### Usage Example

#### Basic Usage

```python
import os
from sr_sec_py_sns_logger import (
    create_security_context,
    warn_missing_context_fields,
    log_record_access,
    fire_and_forget,
    EventType,
    Status,
    ActorType,
    UserRole,
    Category,
)
from concurrent.futures import ThreadPoolExecutor

def handle_request(request_headers, session, request_path, request_method):
    # Auto-extract what we can from request/session/environment
    context = create_security_context(
        request_headers=request_headers,
        session=session,
        request_path=request_path,
        request_method=request_method,
    )
    
    # Optional: warn in development if fields couldn't be extracted
    if os.environ.get('ENV_TYPE') == 'development':
        warn_missing_context_fields(context)
    
    # Use the context - logging function will return error if required fields missing
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            log_record_access,
            **context,                     # All auto-extracted fields
            event_type=EventType.RECORD_ACCESS,
            actor_type=ActorType.HUMAN_INTERNAL,  # Manual: business logic
            user_role=UserRole.ADMIN,              # Manual: from your auth system
            status=Status.SUCCESS,
            category=Category.CUSTOMER_DATA_ACTIONS,
            id_list=['customer-123'],
        )
        
        # fire_and_forget handles the result - if missing fields, it will log error
        fire_and_forget(future, 'record_access')
    
    return {"success": True}

# Example session dict (from your auth system)
session = {
    'user': {'email': 'user@example.com'},
    'expires': '2024-01-01T00:00:00Z'
}

# Example request headers
request_headers = {
    'user-agent': 'Mozilla/5.0...',
    'x-forwarded-for': '1.2.3.4'
}
```

### Required Environment Variables

For full auto-extraction to work, configure these environment variables:

```bash
# Required for cloud_env_type and cloud_env_name
NEXT_PUBLIC_ENVIRONMENT_NAME=production  # or staging, development, etc.
# OR
CLOUD_ENV_TYPE=prod
CLOUD_ENV_NAME=Production

# Required for service_name
SERVICE_NAME=my-python-service

# Required for cloud_env_unique_id
AWS_ACCOUNT_ID=123456789012

# Required for service_account_id
SERVICE_ACCOUNT_ID=arn:aws:iam::123456789012:role/my-role
# OR
AWS_EXECUTION_ROLE_ARN=arn:aws:iam::123456789012:role/my-role
```

### Handling Missing Fields

Auto-extraction is **best-effort** - if environment variables aren't set, the fields will be `None`. The logging functions handle this gracefully by returning a failure response (not raising):

```python
result = log_record_access(**context, event_type=EventType.RECORD_ACCESS, ...)

if result['status'] == 'failure':
    # result['message'] will say "Missing required fields: cloud_env_type, service_name"
    print(result['message'])
```

### Diagnosing Missing Fields in Development

Use `diagnose_security_context()` to get detailed information about what's missing and how to fix it:

```python
from sr_sec_py_sns_logger import create_security_context, diagnose_security_context

context = create_security_context(request_headers, session)
diagnostics = diagnose_security_context(context)

if diagnostics['has_missing']:
    print('Missing fields - set these environment variables:')
    for suggestion in diagnostics['suggestions']:
        print(f"  {suggestion['field']}: {suggestion['env_var']} ({suggestion['description']})")

# Example output:
# Missing fields - set these environment variables:
#   cloud_env_type: CLOUD_ENV_TYPE or NEXT_PUBLIC_ENVIRONMENT_NAME (Environment type)
#   service_name: SERVICE_NAME (Application/service name)
```

---

## 📋 Part 4: Production Readiness

### CloudWatch Monitoring Implementation

**⚠️ CRITICAL REQUIREMENT**: All teams using this security logging library **MUST** implement CloudWatch alarms to monitor for security logging failures. Security logging failures represent a significant security risk.

**Why Required:** Failed security logs create gaps in monitoring and impact incident response.

#### Step 1: Install AWS CloudWatch SDK
```bash
pip install boto3
```

#### Step 2: Create Reusable CloudWatch Metrics Helper

```python
import boto3
import os
import sys
from datetime import datetime, timezone
from typing import Optional

class SecurityLoggingMetrics:
    """
    Reusable CloudWatch metrics helper for security logging failures.
    Integrates with fire-and-forget error handling.
    """
    
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch', region_name=os.environ.get('AWS_REGION', 'us-west-2'))
        self.service_name = os.environ.get('SERVICE_NAME', 'your-service-name')
        self.environment = os.environ.get('ENV_TYPE', 'unknown')
        self.namespace = 'SecurityLogging'
    
    def report_failure(self, event_type: Optional[str] = None) -> None:
        """
        Report security logging failure (metric value = 1).
        This method is also fire-and-forget - won't block if metrics fail.
        
        Args:
            event_type: Optional event type for additional context
        """
        dimensions = [
            {'Name': 'ServiceName', 'Value': self.service_name},
            {'Name': 'Environment', 'Value': self.environment}
        ]
        
        if event_type:
            dimensions.append({'Name': 'EventType', 'Value': event_type})
        
        try:
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=[{
                    'MetricName': 'log_failure',
                    'Value': 1.0,
                    'Unit': 'Count',
                    'Timestamp': datetime.now(timezone.utc),
                    'Dimensions': dimensions
                }]
            )
        except Exception as error:
            # Don't let metrics failures break the app
            print(f'Failed to report security logging failure metric: {error}', file=sys.stderr)

# Global metrics instance
security_metrics = SecurityLoggingMetrics()
```

#### Step 3: Wire Up Error Handler at App Startup

```python
import sr_sec_py_sns_logger as SecurityLogging

def setup_security_logging():
    """Complete security logging setup with monitoring."""
    # Initialize security logging
    SecurityLogging.init_security_logging(
        test_mode=os.environ.get('ENV_TYPE') != 'production'
    )
    
    # Set up error handler that reports to CloudWatch
    def security_error_handler(error_msg, event_type):
        print(f"🚨 Security logging failed for {event_type}: {error_msg}", file=sys.stderr)
        security_metrics.report_failure(event_type)
    
    SecurityLogging.set_security_logging_error_handler(security_error_handler)
    print("✅ Security logging initialized with CloudWatch monitoring")

# Call once at application startup
setup_security_logging()
```

#### Step 4: Use Fire-and-Forget Everywhere

Simple usage - failures automatically get logged + reported:

```python
from concurrent.futures import ThreadPoolExecutor

# In your application code
def handle_user_login(user_email, session_id):
    # Your business logic here...
    
    # Security logging (non-blocking, with automatic failure reporting)
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            SecurityLogging.log_user_login,
            event_type=SecurityLogging.EventType.LOGIN_ATTEMPT,
            actor_identifier=user_email,
            actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
            session_id=session_id,
            user_agent="Mozilla/5.0...",
            user_role=SecurityLogging.UserRole.ADMIN,
            auth_protocol=SecurityLogging.AuthProtocol.FORM_BASED,
            status=SecurityLogging.Status.SUCCESS,
            detail="Successful login"
        )
        SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.LOGIN_ATTEMPT)
    
    # User gets immediate response - no blocking
    return {"status": "success"}
```

#### Step 5: Add CloudWatch Permissions

Add these permissions to your Lambda/service IAM role:

```hcl
{
  Effect = "Allow"
  Action = ["cloudwatch:PutMetricData"]
  Resource = "*"
  Condition = {
    StringEquals = {
      "cloudwatch:namespace" = "SecurityLogging"  # Match your namespace
    }
  }
}
```

#### Step 6: Create CloudWatch Alarms

**Production Environment (Strict Monitoring):**
```hcl
resource "aws_cloudwatch_metric_alarm" "security_logging_failures" {
  alarm_name          = "security-logging-failures-${var.service_name}-prod"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "log_failure"
  namespace           = "SecurityLogging"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "1"    # Any failure triggers alarm
  alarm_description   = "SEV_1: Critical - Security logging failures detected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ServiceName = var.service_name
    Environment = "prod"
  }

  tags = {
    Severity    = "sev_1"
    AlertType   = "security_logging_failure"
    ServiceName = var.service_name
  }
}
```

**Development Environment (Relaxed Monitoring):**
```hcl
resource "aws_cloudwatch_metric_alarm" "security_logging_failures_dev" {
  alarm_name          = "security-logging-failures-${var.service_name}-dev"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "log_failure"
  namespace           = "SecurityLogging"
  period              = "600"  # 10 minutes
  statistic           = "Sum"
  threshold           = "5"    # Higher threshold for dev
  alarm_description   = "SEV_3: Security logging failures in dev environment"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ServiceName = var.service_name
    Environment = "dev"
  }

  tags = {
    Severity    = "sev_3"
    AlertType   = "security_logging_failure"
    ServiceName = var.service_name
  }
}
```

#### Step 7: Set Environment Variables

```bash
# Required environment variables for your Lambda/service
SERVICE_NAME=your-service-name
ENV_TYPE=prod  # or 'dev', 'staging'
AWS_REGION=us-west-2  # Optional, defaults to us-west-2
```

### Reusable Terraform Module (Recommended)

For teams that want a complete, reusable solution, we provide a Terraform module that you can copy from [https://github.com/SunRun/softsec-aws-user-access-review/tree/develop/templates/shared/security-logging-alerts](https://github.com/SunRun/softsec-aws-user-access-review/tree/develop/templates/shared/security-logging-alerts)

[Example module usage](https://github.com/SunRun/softsec-aws-user-access-review/blob/develop/env/dev/uar-perm-ingest/security_alerts.tf):

```hcl
# Security Logging Alerts - Development Environment
# Using the reusable security-logging-alerts module

module "security_logging_alerts" {
  source = "../../../templates/shared/security-logging-alerts"
  
  service_name            = "your-service-name"
  environment             = local.environment
  cloudwatch_namespace    = "SecurityLogging"
  
  # Development settings: relaxed thresholds
  failure_threshold_immediate = 5       # Higher threshold for dev environment
  severity_immediate          = "sev_3" # Lower severity for dev
  enable_sustained_alarm      = false   # No sustained alarm needed in dev
  
  common_tags = local.common_tags
}
```

### Severity Level Guidelines

| Environment | Immediate Threshold | Severity | Rationale |
|-------------|-------------------|----------|-----------|
| **Production** | 1 failure | `sev_1` | Any security logging failure in production is critical |
| **Staging** | 2 failures | `sev_2` | Some tolerance for staging environment |
| **Development** | 5 failures | `sev_3` | Higher tolerance for development noise |

### Monitoring Best Practices

1. **✅ Monitor All Environments**: Even dev failures can indicate code issues
2. **✅ Use Dimensions**: Separate metrics by service and environment
3. **✅ Set Appropriate Thresholds**: Strict for prod, relaxed for dev
4. **✅ Alert the Right Teams**: Route production alerts to security/oncall teams
5. **✅ Test Your Alarms**: Verify alerts fire correctly during testing

### Security Logging Failure Scenarios

Your monitoring should detect these failure types:

- **SNS Publishing Failures**: Network issues, permission problems, topic unavailable
- **AWS Credential Issues**: Expired credentials, insufficient permissions
- **Validation Failures**: Missing required fields, invalid data formats
- **Initialization Failures**: Security logging module setup problems
- **Rate Limiting**: SNS throttling or quota exceeded

### GitHub Actions Setup

**⚠️ Important: Secret Access Request Required**

Before setting up GitHub Actions, you must request access to the organization secret:

1. **Request Secret Access**: Post a message in the `#software-infrastructure-support` Slack channel requesting access to the `SR_SECURITY_GITHUB_ACTION_MODULES` secret for your repository
2. **Include Repository Details**: Provide your repository name and explain that you need this secret to access the security logging submodule
3. **Wait for Approval**: The infrastructure team will grant your repository access to this organization-level secret

**📍 Note About SNS Topic Region:**
The security logging SNS topic is located in **us-west-2**, regardless of where your application runs. AWS SNS supports cross-region publishing, so your application can publish to the us-west-2 topic even if it runs in a different region (e.g., Shanghai/ap-southeast-1). No special configuration needed - just ensure your IAM role has permissions to publish to the us-west-2 SNS topic.

For Python repositories that use this library as a submodule, add this workflow to `.github/workflows/main.yml`:

```yaml
name: Security Logger CI/CD

on:
  pull_request:
    branches: [ master, develop ]
  push:
    branches: [ master, develop ]

permissions:
  contents: read
  id-token: write
  pull-requests: write

jobs:
  build-lambda:
    name: Build Lambda Package
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4.1.7
        with:
          submodules: recursive
          token: ${{ secrets.SR_SECURITY_GITHUB_ACTION_MODULES }}

      - name: Set up Python
        uses: actions/setup-python@v5.1.0
        with:
          python-version: '3.12'

      # Generate a cache key based on the hash of dependencies and source files
      - name: Generate cache key
        id: generate-key
        run: |
          # The key will change if requirements.lock or any .py file changes
          key="lambda-build-${{ runner.os }}-py3.12-$(sha256sum src/lambda/uar-perm-ingest/requirements.lock $(find src/lambda/uar-perm-ingest -name '*.py') | awk '{print $1}' | sha256sum | head -c 32)"
          echo "key=${key}" >> $GITHUB_OUTPUT
        shell: bash

      # Use the cache action to restore the built package if it exists
      - name: Cache Lambda package
        id: cache-lambda
        uses: actions/cache@v4
        with:
          path: dist/
          key: ${{ steps.generate-key.outputs.key }}

      # The build step now ONLY runs if the cache was not found
      - name: Build Lambda package
        if: steps.cache-lambda.outputs.cache-hit != 'true'
        run: |
          echo "Cache miss. Building Lambda package using Docker..."
          cd src/lambda/uar-perm-ingest
          python build.py
        shell: bash

      - name: Upload Lambda package artifacts
        uses: actions/upload-artifact@v4.3.3
        with:
          name: lambda-package
          path: dist/

  terraform-dev:
    needs: build-lambda
    if: github.ref == 'refs/heads/develop' || (github.event_name == 'pull_request' && github.base_ref == 'develop')
    uses: ./.github/workflows/terraform-reusable.yml
    with:
      working-directory: env/dev/uar-perm-ingest
      environment: dev
      component-name: UAR Perm Ingest
      download-artifact: true
      artifact-name: lambda-package
      artifact-path: dist/
    secrets: inherit

  terraform-prod:
    needs: build-lambda
    if: github.ref == 'refs/heads/master' || (github.event_name == 'pull_request' && github.base_ref == 'master')
    uses: ./.github/workflows/terraform-reusable.yml
    with:
      working-directory: env/prod/uar-perm-ingest
      environment: prod
      component-name: UAR Perm Ingest
      download-artifact: true
      artifact-name: lambda-package
      artifact-path: dist/
    secrets: inherit
```

**Important Notes:**
- **Secret Access Required**: Request `SR_SECURITY_GITHUB_ACTION_MODULES` secret access via `#software-infrastructure-support` Slack channel before setup
- Uses `SR_SECURITY_GITHUB_ACTION_MODULES` secret for submodule access
- Includes submodule checkout with `submodules: recursive`
- Caches Lambda builds for faster CI/CD
- Supports both dev and prod deployments via reusable workflows

---

## 📚 Appendices

### Appendix A: Schema Structure

This module implements a standardized flat JSON schema where all fields are at the same level:

#### Standard Fields
**Required fields for every log entry:**

| Field Name | Description | Example Value | Required |
|------------|-------------|---------------|----------|
| `timestamp` | Event timestamp in UTC | `"2025-09-08T20:25:51.000Z"` | ✅ (auto-generated if empty) |
| `event_type` | Dot-notation event identifier | `"login_attempt"`, `"permission_change"` | ✅ |
| `log_category` | High-level event category | `"authn_n_session"` | ✅ |
| `status` | Event outcome | `"status.general.success"` | ✅ |
| `actor_identifier` | Unique actor identifier | `"user@company.com"` | ✅ |
| `actor_type` | Standardized actor type | `"actor.human.internal"` | ✅ |
| `session_id` | Session identifier | `"session-abc-123"` | ✅ |
| `cloud_env_type` | Environment type | `"prod"`, `"stage"`, `"dev"` | ✅ |
| `service_name` | Application/service name | `"elephant_mfe"` | ✅ |
| `service_component_name` | Specific component within a service | `"auth-handler"`, `"payment-processor"` | ❌ Optional |
| `cloud_env_unique_id` | Cloud environment ID | `"aws_account_id"` | ✅ |
| `cloud_env_name` | Environment name | `"ai_team"` | ✅ |
| `service_account_id` | Service account ID | `"sa-log-writer@project.iam"` | ✅ |
| `source_ip_address` | Source IP address | `"203.0.113.54"` | ❌ Optional |
| `cloud_service_api_type` | Cloud service type | `"aws_lambda"` | ❌ Optional |

#### Event-Specific Fields
Additional required fields based on the specific event type. The `detail` field provides context and uses standardized values:

##### Authentication & Session Events
| Event Type | Required Fields | Optional Fields | Detail Field Usage |
|------------|----------------|-----------------|-------------------|
| **User Login** (`login_attempt`) | `user_agent`, `user_role`, `auth_protocol`, `detail`, `status` | `device_id` | Success (`status.general.success`): "1st time login", "login with a successful MFA"<br>Failure (`status.general.failure`): `detail.auth.invalid_credentials`, `detail.auth.account_locked` |
| **MFA Challenge** (`mfa_challenge`) | `user_agent`, `user_role`, `detail`, `mfa_type`, `status` | `device_id` | Success (`status.general.success`): `detail.trigger.user_initiated`<br>Failure (`status.general.failure`): `detail.mfa.invalid_code`, `detail.mfa.expired_code`, `detail.mfa.device_not_enrolled`, `detail.mfa.too_many_attempts` |
| **User Logout** (`user_logout`) | `user_agent`, `user_role`, `detail` | `device_id` | `detail.trigger.user_initiated`, `detail.trigger.session_timeout`, `detail.trigger.admin_initiated` |

##### Authorization & Access Events
| Event Type | Required Fields | Detail Field Usage |
|------------|----------------|-------------------|
| **Permission/Role/Group Change** (`permission_change`) | `target_user_identifier`, `object_changed`, `previous_value`, `new_value` | N/A |
| **User Status Change** (`user_status_change`) | `target_user_identifier`, `detail` | `detail.trigger.admin_initiated`, `detail.trigger.system_policy_violation` |
| **Impersonation** (`impersonation_event`) | `target_user_identifier` | N/A |
| **User Invite** (`user_invite_event`) | `target_user_email`, `assigned_role`, `invite_status` | N/A |

##### API Endpoint Access Events
| Event Type | Required Fields | Detail Field Usage |
|------------|----------------|-------------------|
| **API Request** (`api_request_processed`) | `auth_protocol`, `endpoint_path`, `http_method`, `endpoint_sensitivity`, `detail` | Success: "Successful API call"<br>Failure: `detail.auth.token_expired`, `detail.client.invalid_request` |

##### Customer Data Actions Events
| Event Type | Required Fields |
|------------|----------------|
| **Record Access** (`record_access`) | `endpoint_path`, `data_sensitivity_level`, `id_list` (record_count is auto-calculated) |

##### Key Configuration Changes Events
| Event Type | Required Fields |
|------------|----------------|
| **MFA Status Change** (`mfa_status_change`) | `target_object`, `mfa_id` |
| **Password Change/Reset** (`password_change_reset`) | `target_object` |
| **API Key Lifecycle** (`api_key_lifecycle`) | `target_object` |
| **Auth Mechanism Modification** (`auth_mechanism_modification`) | `target_object` |

### Appendix B: Sample Log Outputs

This section shows the exact JSON structure that gets sent to your SNS topic for key security event types. All examples use current standardized values and schema.

#### User Login Attempt (Success)
```json
{
  "timestamp": "2025-12-13T04:33:12.100224+00:00",
  "event_type": "login_attempt",
  "log_category": "authn_n_session",
  "status": "status.general.success",
  "event_uuid": "1ade00c0-3dde-4d1f-b39e-eea13a472dd2",
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
  "auth_protocol": "auth.protocol.oauth2.jwt",
  "detail": "detail.trigger.user_initiated",
  "device_id": "device-123",
  "caller_function": "login",
  "caller_file": "auth_routes.py"
}
```

#### User Login Attempt (Failure)
```json
{
  "timestamp": "2025-12-13T04:33:12.100224+00:00",
  "event_type": "login_attempt",
  "log_category": "authn_n_session",
  "status": "status.general.failure",
  "event_uuid": "2bce00c0-4dde-5d1f-c39e-ffa14b572ee3",
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
  "auth_protocol": "auth.protocol.form_based",
  "detail": "detail.auth.invalid_credentials",
  "device_id": "",
  "caller_function": "login",
  "caller_file": "auth_routes.py"
}
```

#### API Request Success
```json
{
  "timestamp": "2025-12-13T04:33:12.100224+00:00",
  "event_type": "api_request_processed",
  "log_category": "api_endpoint_access",
  "status": "status.general.success",
  "event_uuid": "3cdf00c0-5dee-6e2g-d49f-gga25c683ff4",
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
  "detail": "detail.not_applicable",
  "caller_function": "get_profile",
  "caller_file": "api_handlers.py"
}
```

> **📝 Note**: All timestamps are in UTC ISO format. The exact structure shown above is what gets sent to your SNS topic and forwarded to your SIEM for analysis and alerting. For additional sample outputs covering all 14 event types, see [`example_publish.py`](example_publish.py).

### Appendix C: W3C Trace Context Support

This library supports [W3C Trace Context](https://www.w3.org/TR/trace-context/) for distributed tracing across your microservices. This allows you to link security events across multiple services to understand complete request flows.

#### What is Trace Context?

Trace context provides a standardized way to track a single request as it flows through multiple services:

- **`trace_id`** (32 hex chars): Unique ID for the entire transaction across all services
- **`span_id`** (16 hex chars): Unique ID for this specific service's operation  
- **`parent_span_id`** (16 hex chars): The span_id of the calling service (optional)

#### How It Works

```
Browser → Gateway → Auth Service → MFA Service
          |         |              |
          v         v              v
   trace_id: 4bf92f3577b34da6a3ce929d0e0e4736 (SAME everywhere)
   span_id:  00f067aa  b7ad6b71   c8be8c9a (DIFFERENT for each)
```

When you query your logs by `trace_id`, you get ALL events from that user's complete journey.

#### Usage Example

```python
from security_logging_sns import SecurityLogging, EventType, Status, AuthProtocol

# 1. Extract from incoming HTTP request
incoming_traceparent = request.headers.get('traceparent')

if incoming_traceparent:
    # Parse: "00-{trace_id}-{parent_span_id}-{flags}"
    parts = incoming_traceparent.split('-')
    trace_id = parts[1]
    parent_span_id = parts[2]
else:
    # Start new trace
    import secrets
    trace_id = secrets.token_hex(16)  # 32 hex chars
    parent_span_id = None

# 2. Generate THIS service's span_id
import secrets
span_id = secrets.token_hex(8)  # 16 hex chars

# 3. Log with trace context
SecurityLogging.log_user_login(
    event_type=EventType.LOGIN_ATTEMPT,
    status=Status.SUCCESS,
    actor_identifier="user@example.com",
    auth_protocol=AuthProtocol.OAUTH2_JWT,
    user_agent="Mozilla/5.0",
    user_role="role.classification.admin",
    # Trace context fields (optional)
    trace_id=trace_id,
    span_id=span_id,
    parent_span_id=parent_span_id
)

# 4. Forward to next service
next_headers = {
    'traceparent': f'00-{trace_id}-{span_id}-01'
}
requests.post('https://next-service/api', headers=next_headers)
```

#### Querying Traces in Athena

Once events are in S3, you can reconstruct the entire request flow:

```sql
-- Get all events for a specific trace
SELECT 
    timestamp,
    event_type,
    service_name,
    span_id,
    parent_span_id,
    status
FROM security_logs
WHERE trace_id = '4bf92f3577b34da6a3ce929d0e0e4736'
ORDER BY timestamp
```

#### Sample Log Output with Trace Context

```json
{
  "timestamp": "2025-11-24T10:30:00Z",
  "event_type": "login_attempt",
  "status": "status.general.success",
  "actor_identifier": "user@example.com",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "parent_span_id": "b7ad6b7169203331",
  "service_name": "auth-service",
  ...
}
```

#### Benefits

✅ **Link Events Across Services**: See the complete user journey  
✅ **Debugging**: Trace failures back to their source  
✅ **Compliance**: "Show me every service that touched this user's data"  
✅ **Performance Analysis**: Identify slow services in the chain  
✅ **Security Forensics**: Reconstruct attack sequences

#### Important Notes

- All trace context fields are **optional** - existing code continues to work  
- Services that don't use trace context just leave these fields empty
- Trace IDs should be cryptographically random (use `secrets.token_hex()`)
- The W3C spec uses lowercase hex only (a-f, not A-F)

### Appendix D: Troubleshooting

#### Common Issues
1. **Import Errors**: Ensure all files are in the same directory or Python path
2. **AWS Credentials**: Check IAM permissions and credential configuration
3. **Validation Failures**: Use constants from `security_log_fields.py`
4. **Test Failures**: Run `python3 -m pip install -r test/requirements-test.txt`
5. **Security Logging Errors**: Ensure your application has the required SNS publish permissions

#### Error Handling
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

**Best Practices:**
```python
# ✅ Good - Check result and handle failures
with ThreadPoolExecutor() as executor:
    future = executor.submit(SecurityLogging.log_user_login, ...)
    SecurityLogging.fire_and_forget(future, SecurityLogging.EventType.LOGIN_ATTEMPT)

# ✅ Good - Use constants from security_log_fields
result = SecurityLogging.log_user_login(
    actor_type=SecurityLogging.ActorType.HUMAN_INTERNAL,
    user_role=SecurityLogging.UserRole.ADMIN,
    detail=SecurityLogging.Detail.INVALID_CREDENTIALS
)
```

#### Validation & Error Handling

The module provides comprehensive validation:

1. **Crash-Safe**: All function parameters have empty string defaults
2. **Standard Field Validation**: Returns failure message if required standard fields are missing
3. **Event-Specific Validation**: Returns failure message if required event-specific fields are missing
4. **Never Crashes**: Invalid calls return `{"status": "failure", "message": "..."}` instead of throwing exceptions

**Example validation failure:**
```python
# Missing required fields
result = SecurityLogging.log_user_login(
    actor_identifier="user@company.com"
    # Missing other required fields
)
# Returns: {"status": "failure", "message": "Required fields missing: actor_type, session_id, cloud_env_type, service_name, cloud_env_unique_id, cloud_env_name, service_account_id"}
```

### Appendix E: Module Structure

```
sr-sec-py-sns-logger/
├── __init__.py                    # Main module exports
├── security_logging_sns.py        # Core logging functions
├── security_log_fields.py         # Field constants and validation
├── sns_publisher.py              # AWS SNS publishing logic
├── example_publish.py            # Production-ready examples
├── test/
│   ├── test_security_logging.py  # Unit tests
│   ├── pytest.ini               # Test configuration
│   └── requirements-test.txt     # Test dependencies
└── README.md                     # This documentation
```

### Appendix F: Testing & Development

#### Running Tests
```bash
# Unit tests (no AWS credentials required)
cd test/
python3 -m unittest test_security_logging -v

# End-to-end testing with examples
python3 example_publish.py
```

#### Test Coverage
The unit tests cover:
- ✅ **Core Functions**: User login, API request, and other logging functions
- ✅ **Initialization**: Proper setup in test mode
- ✅ **Error Handling**: Missing fields and invalid values handled gracefully
- ✅ **Validation**: Standardized field validation
- ✅ **Fire-and-Forget**: Non-blocking behavior, error handling, concurrent usage

### Appendix G: Configuration Options

#### Initialization Parameters

```python
# Production initialization
SecurityLogging.init_security_logging()

# Development/Testing only
SecurityLogging.init_security_logging(
    test_mode=True  # Prints to console instead of sending to security team
)
```

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `test_mode` | bool | No | Enable test mode (prints to console, no security logging) | `False` |

**🔒 Security First**: Pre-configured for centralized security monitoring. No configuration required for production use.

#### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|  
| `AWS_ACCESS_KEY_ID` | AWS credentials (if not using IAM roles) | `YOUR_ACCESS_KEY_ID` |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials (if not using IAM roles) | `YOUR_SECRET_ACCESS_KEY` |

#### AWS Permissions Required

Your application's IAM role or user needs the following permission for security logging:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:us-west-2:000576341507:sr-sec-logging-log-topic-prod"
        }
    ]
}
```

---

## 🚀 **Requesting New Features & Field Values**

If you need additional event types, field values, or functionality that isn't currently supported in the security logging framework, you can request enhancements:

### **Current Process:**
📧 **Contact the Security Logging Team:**
- **Raul Reutov**: [raul.reutov@sunrun.com](mailto:raul.reutov@sunrun.com)
- **Jeffory Shields**: [jeffory.shields@sunrun.com](mailto:jeffory.shields@sunrun.com)

### **What to Include in Your Request:**
1. **🎯 Business Justification**: Why is this new field/event type needed?
2. **📋 Technical Details**: Specific field names, values, or event types required
3. **🔍 Use Case Description**: How will this be used in your application?
4. **⏰ Timeline**: When do you need this implemented?
5. **📊 Impact Assessment**: How many applications/teams will benefit from this change?

### **Types of Requests We Support:**
- ✅ New event types for emerging security use cases
- ✅ Additional standardized field values (e.g., new user roles, detail values)
- ✅ New authentication protocols or MFA types
- ✅ Enhanced validation logic or error handling
- ✅ Additional data sensitivity classifications

### **Response Timeline:**
- **Initial Response**: Within 2 business days
- **Implementation**: Varies based on complexity and security review requirements
- **Testing & Rollout**: Coordinated with requesting teams

> **📝 Note**: The request process will evolve in the future as the security logging framework matures. We'll update this section with new procedures as they become available.

---

## 📞 Support & Contact

### Getting Help
- **Documentation**: This README contains comprehensive usage information
- **Examples**: See `example_publish.py` for working integration examples
- **Unit Tests**: `test_security_logging.py` shows expected behavior for all functions
- **Error Messages**: All validation errors include specific guidance on fixing issues

### Internal Support
For internal support and questions:
- Check this documentation first - it's comprehensive
- Review the unit tests for expected behavior examples
- Run `python3 example_publish.py` to see working integration examples
- Use test mode (`test_mode=True`) for debugging without AWS credentials

---

*This documentation is comprehensive and designed to enable full understanding and implementation of the security logging module. For additional questions or clarifications, refer to the code comments and unit tests which serve as the definitive specification.*