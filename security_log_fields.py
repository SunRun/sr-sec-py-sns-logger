# File: security_log_fields.py

# Status values for event outcomes
class Status:
    SUCCESS = "status.general.success"
    FAILURE = "status.general.failure"

"""
Actor types define WHO or WHAT is performing the action

Choose the type that best matches the entity initiating the event:
- HUMAN: A person directly interacting with the system
- SERVICE: An application, microservice, or automated agent acting on behalf of someone
- SYSTEM: The application itself performing automated actions

Then specify the relationship (INTERNAL/PARTNER/CUSTOMER)
"""
class ActorType:
    # Sunrun employee or contractor (e.g., admin, developer, support rep)
    HUMAN_INTERNAL = "actor.human.internal"
    
    # Partner organization employee (e.g., installer, vendor user)
    HUMAN_PARTNER = "actor.human.partner"
    
    # Sunrun customer or homeowner
    HUMAN_CUSTOMER = "actor.human.customer"
    
    # Internal Sunrun service/microservice acting on behalf of a user (e.g., API gateway, auth service, backend job)
    SERVICE_INTERNAL = "actor.service.internal"
    
    # Partner's service or API integration acting on behalf of their users (e.g., partner's mobile app, third-party system)
    SERVICE_PARTNER = "actor.service.partner"
    
    # Customer-owned service or application (e.g., customer's home automation system making API calls)
    SERVICE_CUSTOMER = "actor.service.customer"
    
    # The application itself performing scheduled/automated tasks with no external trigger (e.g., cron jobs, cleanup tasks, system maintenance)
    SYSTEM_SELF = "actor.system.self"

# Log categories
class LogCategory:
    AUTHN_SESSION = "authn_n_session"
    AUTHZ_ACCESS = "authz_n_access"
    API_ENDPOINT_ACCESS = "api_endpoint_access"
    CUSTOMER_DATA_ACTIONS = "customer_data_actions"
    KEY_CONFIG_CHANGES = "key_config_changes"

# Event types - simplified based on specification
class EventType:
    # Authentication & Session
    LOGIN_ATTEMPT = "login_attempt"  # Use with Status.SUCCESS or Status.FAILURE
    USER_LOGOUT = "user_logout"
    MFA_CHALLENGE = "mfa_challenge"
    
    # Authorization & Access
    PERMISSION_CHANGE = "permission_change"
    USER_STATUS_CHANGE = "user_status_change"
    IMPERSONATION_EVENT = "impersonation_event"
    USER_INVITE_EVENT = "user_invite_event"
    
    # API Endpoint Access
    API_REQUEST_PROCESSED = "api_request_processed"
    
    # Customer Data Actions
    MULTI_RECORD_ACCESS = "multi_record_access"
    SINGLE_RECORD_ACCESS = "single_record_access"
    
    # Key Configuration Changes
    MFA_STATUS_CHANGE = "mfa_status_change"
    PASSWORD_CHANGE_RESET = "password_change_reset"
    API_KEY_LIFECYCLE = "api_key_lifecycle"
    AUTH_MECHANISM_MODIFICATION = "auth_mechanism_modification"


# Authentication protocols using standardized format
class AuthProtocol:
    # Basic username/password authentication
    BASIC_AUTH = "auth.protocol.basic_auth"           # HTTP Basic Authentication
    FORM_BASED = "auth.protocol.form_based"           # Form-based username/password login
    
    # Token-based authentication
    API_KEY = "auth.protocol.api_key"
    M2M_TOKEN = "auth.protocol.m2m_token"
    SESSION_COOKIE = "auth.protocol.session_cookie"
    
    # OAuth2 variants
    OAUTH2_JWT = "auth.protocol.oauth2.jwt"
    OAUTH2_CLIENT_CREDENTIALS = "auth.protocol.oauth2.client_credentials"
    OAUTH2_AUTHORIZATION_CODE = "auth.protocol.oauth2.authorization_code"
    OAUTH2_IMPLICIT = "auth.protocol.oauth2.implicit"
    OAUTH2_PASSWORD_GRANT = "auth.protocol.oauth2.password_grant"
    
    # SSO protocols
    SAML = "auth.protocol.saml"
    OIDC = "auth.protocol.oidc"
    
    # Special cases
    NONE = "auth.protocol.none"

# Detail values for various contexts
class Detail:
    # Authentication failure reasons
    INVALID_CREDENTIALS = "detail.auth.invalid_credentials"
    ACCOUNT_LOCKED = "detail.auth.account_locked"
    IP_RESTRICTED = "detail.auth.ip_restricted"
    MFA_REQUIRED = "detail.auth.mfa_required"
    POLICY_VIOLATION = "detail.auth.policy_violation"
    CAPTCHA_FAILURE = "detail.auth.captcha_failure"
    TOKEN_EXPIRED = "detail.auth.token_expired"
    TOKEN_INVALID = "detail.auth.token_invalid"
    UNAUTHORIZED_ACCESS = "detail.auth.unauthorized_access"
    RATE_LIMIT_EXCEEDED = "detail.auth.rate_limit_exceeded"
    
    # Action/Status Change Triggers
    USER_INITIATED = "detail.trigger.user_initiated"
    ADMIN_INITIATED = "detail.trigger.admin_initiated"
    SYSTEM_AUTOMATED = "detail.trigger.system_automated"
    SYSTEM_POLICY_VIOLATION = "detail.trigger.system_policy_violation"
    SESSION_TIMEOUT = "detail.trigger.session_timeout"
    CONCURRENT_SESSION = "detail.trigger.concurrent_session"
    FAILED_ATTEMPTS_THRESHOLD = "detail.trigger.failed_attempts_threshold"
    
    # General System/Operational
    INTERNAL_ERROR = "detail.system.internal_error"
    SERVICE_UNAVAILABLE = "detail.system.service_unavailable"
    MAINTENANCE = "detail.system.maintenance"
    INVALID_REQUEST = "detail.client.invalid_request"
    NOT_APPLICABLE = "detail.not_applicable"
    
    # API Key Lifecycle Actions
    API_KEY_CREATED = "detail.api_key.created"
    API_KEY_REVOKED = "detail.api_key.revoked"
    API_KEY_PERMISSIONS_MODIFIED = "detail.api_key.permissions_modified"
    
    # Auth Mechanism Modification Types
    SSO_CONFIG_CREATED = "detail.auth.sso_config_created"
    SSO_CONFIG_MODIFIED = "detail.auth.sso_config_modified"
    SSO_CONFIG_DELETED = "detail.auth.sso_config_deleted"
    LOCAL_AUTH_ENABLED = "detail.auth.local_auth_enabled"
    LOCAL_AUTH_DISABLED = "detail.auth.local_auth_disabled"
    
    # User Status Actions
    USER_DISABLED = "detail.action.user_disabled"
    USER_ENABLED = "detail.action.user_enabled"
    USER_DELETED = "detail.action.user_deleted"
    USER_LOCKED = "detail.action.user_locked"
    USER_UNLOCKED = "detail.action.user_unlocked"
    
    # Impersonation Actions
    IMPERSONATION_START = "detail.action.impersonation_start"
    IMPERSONATION_STOP = "detail.action.impersonation_stop"
    
    # Customer Data Actions
    VIEW_LIST = "detail.action.view_list"
    MODIFY_CUSTOMER_DATA = "detail.action.modify_customer_data"
    EXPORT_REPORT = "detail.action.export_report"
    VIEW_RECORD = "detail.action.view_record"
    EDIT_RECORD = "detail.action.edit_record"
    
    # MFA Actions
    MFA_DISABLED = "detail.action.mfa_disabled"
    MFA_ENABLED = "detail.action.mfa_enabled"
    NEW_MFA_DEVICE = "detail.action.new_mfa_device"
    
    # Password Actions
    PASSWORD_CHANGE = "detail.action.password_change"
    PASSWORD_RESET = "detail.action.password_reset"
    
    # Auth Mechanism Actions
    NEW_SSO_PROVIDER = "detail.action.new_sso_provider"
    ENABLE_LOCAL_AUTHN = "detail.action.enable_local_authn"
    DISABLE_SSO = "detail.action.disable_sso"

# MFA types
class MfaType:
    SMS = "sms"
    TOTP = "totp"
    PUSH = "push"
    EMAIL = "email"
    OKTA_VERIFY = "okta_verify"
    AUTHENTICATOR_APP = "authenticator_app"
    HARDWARE_TOKEN = "hardware_token"
    BIOMETRIC = "biometric"
    BACKUP_CODES = "backup_codes"

# HTTP methods using standardized format
class HttpMethod:
    GET = "http.method.GET"
    POST = "http.method.POST"
    PUT = "http.method.PUT"
    PATCH = "http.method.PATCH"
    DELETE = "http.method.DELETE"
    HEAD = "http.method.HEAD"
    OPTIONS = "http.method.OPTIONS"

# Cloud environment types
class CloudEnvType:
    PROD = "prod"
    STAGE = "stage"
    TEST = "test"
    DEV = "dev"

# Cloud service API types
class CloudServiceApiType:
    AWS_LAMBDA = "aws_lambda"
    GKE_NAMESPACE = "gke_namespace"
    EC2_INSTANCE = "ec2_instance"
    ECS_SERVICE = "ecs_service"

# Data sensitivity levels using standardized format
class DataSensitivityLevel:
    PUBLIC = "sensitivity.level.public"
    INTERNAL = "sensitivity.level.internal"
    CONFIDENTIAL = "sensitivity.level.confidential"
    PII_BASIC = "sensitivity.level.pii_basic"
    PII_FINANCIAL = "sensitivity.level.pii_financial"
    PII_HEALTH = "sensitivity.level.pii_health"
    CREDENTIAL_MANAGEMENT = "sensitivity.level.credential_management"
    SYSTEM_ADMIN = "sensitivity.level.system_admin"
    AUTHENTICATION = "sensitivity.level.authentication"

# Endpoint sensitivity levels using standardized format
class EndpointSensitivity:
    PUBLIC = "sensitivity.level.public"
    INTERNAL = "sensitivity.level.internal"
    CONFIDENTIAL = "sensitivity.level.confidential"
    PII_BASIC = "sensitivity.level.pii_basic"
    PII_FINANCIAL = "sensitivity.level.pii_financial"
    PII_HEALTH = "sensitivity.level.pii_health"
    CREDENTIAL_MANAGEMENT = "sensitivity.level.credential_management"
    SYSTEM_ADMIN = "sensitivity.level.system_admin"
    AUTHENTICATION = "sensitivity.level.authentication"

# User roles (example - should be replaced with actual roles in your system)
class UserRole:
    ADMIN = "role.classification.admin"
    SALES_REP = "role.classification.sales_rep"
    CUSTOMER_SUPPORT = "role.classification.customer_support"
    PARTNER_ADMIN = "role.classification.partner_admin"
    CUSTOMER_USER = "role.classification.customer_user"

# Invite status values
class InviteStatus:
    SENT = "sent"
    ACCEPTED = "accepted"
    REVOKED = "revoked"
    EXPIRED = "expired"

# Validation lists for standardized values
VALID_EVENT_TYPES = [
    EventType.LOGIN_ATTEMPT,       # Consolidated login event (use with status field)
    EventType.USER_LOGOUT,
    EventType.MFA_CHALLENGE,
    EventType.PERMISSION_CHANGE,
    EventType.USER_STATUS_CHANGE,
    EventType.IMPERSONATION_EVENT,
    EventType.USER_INVITE_EVENT,
    EventType.API_REQUEST_PROCESSED,
    EventType.MULTI_RECORD_ACCESS,
    EventType.SINGLE_RECORD_ACCESS,
    EventType.MFA_STATUS_CHANGE,
    EventType.PASSWORD_CHANGE_RESET,
    EventType.API_KEY_LIFECYCLE,
    EventType.AUTH_MECHANISM_MODIFICATION
]
