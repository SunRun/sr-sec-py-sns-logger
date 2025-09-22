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

## 📋 **CRITICAL FIRST STEP: Review Required Fields**

**⚠️ MANDATORY REQUIREMENT**: Before implementing any security logging functions, you **MUST** thoroughly review both the standardized field definitions and the organizational logging framework:

### 🔗 **Required Reading**:
1. **[Minimum Standard Logging Framework](https://sunrun.jira.com/wiki/spaces/SUNSEC/pages/4267769872/Minimum+Standard+Logging+Framework)** - Organizational security logging standards and requirements
2. **[security_log_fields.py](https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/security_log_fields.py)** - Technical field definitions and constants

**Why This Review is Critical:**

1. **🎯 Standardized Values Required**: All security log events MUST use the predefined constants from `security_log_fields.py`. Custom or arbitrary string values will cause validation failures.

2. **📊 Schema Compliance**: The security logging system enforces strict schema validation. Understanding the required fields for each event type speeds up onboarding.

3. **🔍 Audit & Compliance**: Security teams and auditors expect consistent, standardized field values across all applications. Deviating from the standard creates compliance gaps.

4. **🛠️ Implementation Success**: Reviewing the field definitions first will save significant development time by preventing common validation errors.

### **Key Areas to Review:**

- **Event Types**: Complete list of supported security events (`EventType` class)
- **Actor Types**: Standardized actor classifications (`ActorType` class) 
- **Status Values**: Success/failure indicators (`Status` class)
- **Detail Values**: Contextual information for events (`Detail` class)
- **User Roles**: Role classifications for your organization (`UserRole` class)
- **Required vs Optional Fields**: Understanding which fields are mandatory for each event type

### **Implementation Workflow:**

1. **📋 Step 1**: Review the [Minimum Standard Logging Framework](https://sunrun.jira.com/wiki/spaces/SUNSEC/pages/4267769872/Minimum+Standard+Logging+Framework) to understand organizational requirements
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

## 🚨 **REQUIRED: Security Logging Failure Monitoring**

**⚠️ CRITICAL REQUIREMENT**: All teams using this security logging library **MUST** implement CloudWatch alarms to monitor for security logging failures. Security logging failures represent a significant security risk and compliance violation.

### Why Monitoring is Required

1. **Security Blind Spots**: Failed security logs create gaps in security monitoring
2. **Compliance Risk**: Missing security logs can violate audit and compliance requirements  
3. **Incident Response**: Security teams need to know immediately when logging fails
4. **Data Integrity**: Ensures complete security event coverage for forensics

### Quick Implementation Guide

#### Step 1: Add CloudWatch Metrics to Your Code

Add this simple metric reporting to your security logging implementation:

```python
import boto3
from datetime import datetime, timezone

class SecurityLoggingMetrics:
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch')
        self.service_name = os.environ.get('SERVICE_NAME', 'your-service-name')
        self.namespace = os.environ.get('CLOUDWATCH_NAMESPACE', 'SecurityLogging')
    
    def report_failure(self):
        """Report security logging failure (metric value = 1)"""
        self.cloudwatch.put_metric_data(
            Namespace=self.namespace,
            MetricData=[{
                'MetricName': 'log_failure',
                'Value': 1.0,
                'Unit': 'Count',
                'Timestamp': datetime.now(timezone.utc),
                'Dimensions': [
                    {'Name': 'ServiceName', 'Value': self.service_name},
                    {'Name': 'Environment', 'Value': os.environ.get('ENV_TYPE', 'unknown')}
                ]
            }]
        )

# Global metrics instance
security_metrics = SecurityLoggingMetrics()

# Use in your security logging code:
result = security_logging_sns.log_user_login(...)
if result.get("status") == "failure":
    security_metrics.report_failure()  # Push failure metric
    logger.warning(f"Security logging failed: {result.get('message')}")
```

#### Step 2: Add CloudWatch Permissions

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

#### Step 3: Create CloudWatch Alarms

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

#### Step 4: Set Environment Variables

```bash
# Required environment variables for your Lambda/service
SERVICE_NAME=your-service-name
CLOUDWATCH_NAMESPACE=YourTeam/SecurityLogging  # Optional, defaults to 'SecurityLogging'
ENV_TYPE=prod  # or 'dev', 'staging'
```

### Reusable Terraform Module (Recommended)

For teams that want a complete, reusable solution, we provide a Terraform module:

```hcl
# Use the reusable security logging alerts module
module "security_logging_alerts" {
  source = "git::https://github.com/YourOrg/terraform-modules//security-logging-alerts"
  
  service_name         = "your-service-name"
  environment          = "prod"
  cloudwatch_namespace = "YourTeam/SecurityLogging"
  
  # Production: Strict thresholds
  failure_threshold_immediate = 1      # Any failure is critical
  severity_immediate          = "sev_1"
  
  # Optional: Sustained failure monitoring
  failure_threshold_sustained = 3      # 3+ failures indicates systematic issue
  severity_sustained          = "sev_2"
  
  common_tags = {
    Team        = "YourTeam"
    Application = "YourApp"
    Environment = "prod"
  }
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

### Compliance and Audit Requirements

- **SOC 2**: Requires monitoring of security logging systems
- **PCI DSS**: Mandates alerting on security system failures
- **GDPR**: Requires audit trail completeness verification
- **Internal Audits**: Security teams must be notified of logging gaps

---

##  📦 Installation & Integration

### Step 1: Add as Git Submodule
```bash
git submodule add https://github.com/SunRun/sr-sec-py-sns-logger.git
```

### Step 2: Create Symlinks for IDE Support
Navigate to your application source directory and create symlinks:

```bash
ln -sf ../../sr-sec-py-sns-logger/security_logging_sns.py security_logging_sns.py
ln -sf ../../sr-sec-py-sns-logger/security_log_fields.py security_log_fields.py
ln -sf ../../sr-sec-py-sns-logger/sns_publisher.py sns_publisher.py
```

### Step 3: Configure AWS Permissions
Add SNS permissions to your application's IAM role:

```hcl
# Terraform example - replace YOUR_SECURITY_ACCOUNT_ID
{
  Effect = "Allow"
  Action = ["sns:Publish"]
  Resource = "arn:aws:sns:${var.aws_region}:YOUR_SECURITY_ACCOUNT_ID:sr-sec-logging-log-topic-${local.environment}"
}

# If SNS topic is KMS encrypted, also add:
{
  Effect = "Allow"
  Action = [
    "kms:GenerateDataKey",
    "kms:Decrypt"
  ]
  Resource = "arn:aws:kms:${var.aws_region}:YOUR_SECURITY_ACCOUNT_ID:key/*"
}

# REQUIRED: CloudWatch metrics permissions for failure monitoring
{
  Effect = "Allow"
  Action = ["cloudwatch:PutMetricData"]
  Resource = "*"
  Condition = {
    StringEquals = {
      "cloudwatch:namespace" = "SecurityLogging"
    }
  }
}
```

### Step 4: Initialize in Your Application
```python
import security_logging_sns

# Initialize once at application startup
try:
    security_logging_sns.init_security_logging()
except Exception as e:
    logging.getLogger(__name__).warning(f"Failed to initialize security logging: {e}")
    # REQUIRED: Report initialization failure
    security_metrics.report_failure()
```

### Step 5: GitHub Actions Setup
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
          token: ${{ secrets.SECURITY_GITHUB_ACTION_PACKAGES }}

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
- Uses `SECURITY_GITHUB_ACTION_PACKAGES` secret for submodule access
- Includes submodule checkout with `submodules: recursive`
- Caches Lambda builds for faster CI/CD
- Supports both dev and prod deployments via reusable workflows

### Step 6: Testing and Implementation Help
For comprehensive implementation examples and testing of all 14 security event types, see [`test_publish.py`](test_publish.py). This test file demonstrates:
- ✅ Proper usage of all security logging functions
- ✅ Required field validation and examples  
- ✅ Realistic test data with proper constants
- ✅ Complete integration patterns
- ✅ End-to-end SNS publishing verification

Run the test: `python3 test_publish.py`

### Step 7: Use in Your Code
```python
# Example: Log user authentication
result = security_logging_sns.log_user_login(
    event_type=EventType.LOGIN_SUCCESS,
    actor_identifier="user@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-123",
    cloud_env_type=CloudEnvType.PROD,
    service_name="auth-service",
    cloud_env_unique_id="123456789012",
    cloud_env_name="production",
    service_account_id="lambda-execution-role",
    user_agent="Mozilla/5.0...",
    user_role=UserRole.ADMIN,
    status=Status.SUCCESS,
    detail=Detail.USER_INITIATED
)

# REQUIRED: Handle failures gracefully and report metrics
if result.get("status") == "failure":
    security_metrics.report_failure()  # Push CloudWatch metric
    logger.warning(f"Security logging failed: {result.get('message')}")
```

### 🚨 Key Requirements
- ✅ **Arrays for customer_id_list**: Pass `["id1", "id2"]` not `"id1,id2"`
- ✅ **No source_ip_address for Lambda**: Omit this field for serverless functions  
- ✅ **Use standardized constants**: Import from `security_log_fields.py`
- ✅ **IMPLEMENT FAILURE MONITORING**: CloudWatch alarms are mandatory for all teams

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
        security_logging_sns.init_security_logging()
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
### Step 1: No Configuration Required
The security logging module is pre-configured for production use. Simply initialize and start logging security events.

**Production Configuration:**
- ✅ **Centralized Security Logging**: All events automatically sent to the security team's monitoring system
- ✅ **Compliance Ready**: Pre-configured for security audit and compliance requirements
- ✅ **Zero Configuration**: No setup required for production deployments

### Step 2: Initialize Security Logging
At the entry point of your application (e.g., lambda_handler), initialize the security logging module. This should be done once at application startup.

```python
# File: my_application.py

import os
import security_logging_sns

# Initialize security logging at the global scope for efficiency
# Automatically configured for production security monitoring
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
# Production initialization
security_logging_sns.init_security_logging()

# Development/Testing only
security_logging_sns.init_security_logging(
    test_mode=True  # Prints to console instead of sending to security team
)
```

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `test_mode` | bool | No | Enable test mode (prints to console, no security logging) | `False` |

**🔒 Security First**: Pre-configured for centralized security monitoring. No configuration required for production use.

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|  
| `AWS_ACCESS_KEY_ID` | AWS credentials (if not using IAM roles) | `YOUR_ACCESS_KEY_ID` |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials (if not using IAM roles) | `YOUR_SECRET_ACCESS_KEY` |

### AWS Permissions Required

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

## 📝 Key Function Examples

### User Login
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

### API Request
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

### Permission Change
```python
result = security_logging_sns.log_permission_change(
    actor_identifier="admin@company.com",
    actor_type=ActorType.HUMAN_INTERNAL,
    session_id="session-admin-perm",
    cloud_env_type=CloudEnvType.PROD,
    service_name="user-management-api",
    cloud_env_unique_id="123456789012",
    cloud_env_name="prod-us-east-1",
    service_account_id="sa-user-mgmt@project.iam.gserviceaccount.com",
    target_user_identifier="newuser@company.com",
    permission_name="Role",
    change_type="granted",
    source_ip_address="10.0.1.25"
)
```

> **📝 Note**: For complete examples of all 14 available functions, see [`test_publish.py`](test_publish.py).

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
- `test_mode` (bool, optional): Enable test mode for development (prints to console instead of security logging)

**Raises:**
- `Exception`: If security logging system initialization fails

**Examples:**
```python
# Production - ready to use
security_logging_sns.init_security_logging()

# Development/Testing only
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

## ⚠️ Error Handling

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
result = security_logging_sns.log_user_login(...)
if result["status"] == "failure":
    security_metrics.report_failure()  # Push CloudWatch metric
    app_logger.warning(f"Security logging failed: {result['message']}")

# ✅ Good - Use constants from security_log_fields
from security_log_fields import ActorType, UserRole, Detail

result = security_logging_sns.log_user_login(
    actor_type=ActorType.HUMAN_INTERNAL,
    user_role=UserRole.ADMIN,
    detail=Detail.INVALID_CREDENTIALS
)
```

**Common Issues:**
- **Initialization**: Call `init_security_logging()` before using any logging functions
- **Missing Fields**: Provide all required fields with non-empty values
- **Invalid Values**: Use constants from `security_log_fields.py`
- **AWS Errors**: Check credentials, permissions, and SNS topic existence

## 🧪 Testing & Development

The module includes essential testing organized in the `test/` directory:

### Test Structure
```
test/
├── test_security_logging.py      # Core unit tests
├── run_tests.py                  # Test runner
├── pytest.ini                   # Pytest configuration
└── requirements-test.txt         # Test dependencies
```

### Running Tests

#### **Unit Tests** 🔬
Test core functionality in test mode (no AWS credentials required):
```bash
cd test/
python3 -m unittest test_security_logging -v
```

#### **Run All Tests**
```bash
cd test/
python3 run_tests.py
```

### Install Testing Dependencies
```bash
pip install -r test/requirements-test.txt
```

### Run Tests with Coverage (using pytest)
```bash
cd test/
pytest --cov=../security_logging_sns --cov=../security_log_fields --cov-report=html
```

### Test Coverage
The unit tests cover:
- ✅ **Core Functions**: User login, API request, and other logging functions
- ✅ **Initialization**: Proper setup in test mode
- ✅ **Error Handling**: Missing fields and invalid values handled gracefully
- ✅ **Validation**: Standardized field validation
- ✅ **Test Mode**: Functions work without AWS credentials

### Development Setup
```bash
# Install development dependencies
pip install -r test/requirements-test.txt

# Run all tests
python3 test/run_tests.py

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
| **`test/`** | **Testing directory** | **Essential test files** |
| `test/test_security_logging.py` | Unit tests | Core functionality tests for all logging functions |
| `test/run_tests.py` | Test runner | Unified test execution script |
| `test/pytest.ini` | Pytest config | Test configuration and settings |
| `test/requirements-test.txt` | Test dependencies | Testing-specific package requirements |

### Dependencies

- **`boto3`**: AWS SDK for Python (SNS publishing)
- **`pytest`**: Testing framework (development only)
- **`pytest-cov`**: Test coverage reporting (development only)

### Python Version Compatibility
- **Minimum**: Python 3.7+
- **Recommended**: Python 3.9+
- **Tested**: Python 3.8, 3.9, 3.10, 3.11

## 📄 Sample Log Outputs

This section shows the exact JSON structure that gets sent to your SNS topic for key security event types. All examples use current standardized values and schema.

### User Login Success
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

### API Request Success
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

### Single Customer Record Access
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

### Multi-Record Data Access
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

> **📝 Note**: All timestamps are in UTC ISO format. The exact structure shown above is what gets sent to your SNS topic and forwarded to your SIEM for analysis and alerting. For additional sample outputs covering all 14 event types, see [`test_publish.py`](test_publish.py).

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

### Common Issues
1. **Import Errors**: Ensure all files are in the same directory or Python path
2. **AWS Credentials**: Check IAM permissions and credential configuration
3. **Validation Failures**: Use constants from `security_log_fields.py`
4. **Test Failures**: Run `python3 -m pip install -r test/requirements-test.txt`
5. **Security Logging Errors**: Ensure your application has the required SNS publish permissions

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

---

## 📚 Appendix: Why We Don't Extract Base Logs from React Logs

While it might seem efficient to extract security events from existing React application logs, this approach creates significant challenges:

### **🚫 Key Issues with React Log Extraction:**

1. **Lack of Uniformity**: Each React application uses different logging libraries, formats, and conventions
2. **Processing Overhead**: Would require sophisticated parsing logic for each application's unique log format
3. **Security Risks**: React logs rarely contain all required security logging fields
4. **Data Integrity**: Important security context may be lost during extraction
5. **Maintenance Burden**: Each application change could break the extraction logic

```javascript
// Example of inconsistent React logging patterns:

// Application A - Custom logger
logger.info(`User ${userId} accessed ${resource}`, { timestamp: Date.now() });

// Application B - Console logging  
console.log('LOGIN:', user.email, 'SUCCESS', new Date().toISOString());

// Application C - Structured logging
log.event('user.login', { user: user.id, status: 'success', ip: req.ip });
```

### **✅ Why Direct Security Logging is Superior**

- **Consistent Schema**: Every security event follows the same standardized structure
- **Required Fields**: All mandatory security fields are guaranteed to be present
- **Real-Time Delivery**: Security events are sent directly to monitoring systems
- **Compliance Ready**: Meets audit and regulatory requirements out of the box
- **Single Integration**: One-time implementation per application

### **🎯 Recommendation**

**Always implement direct security logging using this framework rather than attempting to extract security events from application logs.** The initial integration effort is minimal compared to the ongoing complexity and reliability issues of log extraction approaches.

For applications that already have extensive logging, use this security logging framework **in addition to** (not instead of) existing application logs. Application logs serve debugging and operational purposes, while security logs serve compliance and security monitoring purposes.
