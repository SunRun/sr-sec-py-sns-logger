# File: security_log_fields.py

# Status values for event outcomes
class Status:
    SUCCESS = "status.general.success"
    FAILURE = "status.general.failure"

# Actor types using the new standardized format
class ActorType:
    HUMAN_INTERNAL = "actor.human.internal"
    HUMAN_PARTNER = "actor.human.partner"
    HUMAN_CUSTOMER = "actor.human.customer"
    SERVICE_INTERNAL = "actor.service.internal"
    SERVICE_PARTNER = "actor.service.partner"
    SERVICE_CUSTOMER = "actor.service.customer"
    SYSTEM_SELF = "actor.system.self"

# Log categories
class LogCategory:
    AUTHN_SESSION = "authn_n_session"
    AUTHZ_ACCESS = "authz_n_access"
    API_ENDPOINT_ACCESS = "api_endpoint_access"
    CUSTOMER_DATA_ACTIONS = "customer_data_actions"
    KEY_CONFIG_CHANGES = "key_config_changes"

# Event types using standardized dot notation format
class EventType:
    # Authentication & Session
    LOGIN_SUCCESS = "authn.login.success"
    LOGIN_FAILURE = "authn.login.failure"
    LOGOUT_USER_INITIATED = "authn.logout.user_initiated"
    LOGOUT_SESSION_TIMEOUT = "authn.logout.session_timeout"
    LOGOUT_ADMIN_INITIATED = "authn.logout.admin_initiated"
    MFA_CHALLENGE_SUCCESS = "authn.mfa.challenge_success"
    MFA_CHALLENGE_FAILURE = "authn.mfa.challenge_failure"
    PASSWORD_CHANGE = "authn.password.change"
    PASSWORD_RESET = "authn.password.reset"
    MFA_STATUS_ENABLED = "authn.mfa.status_enabled"
    MFA_STATUS_DISABLED = "authn.mfa.status_disabled"
    MFA_DEVICE_ADDED = "authn.mfa.device_added"
    MFA_DEVICE_REMOVED = "authn.mfa.device_removed"
    SSO_CONFIG_CREATED = "authn.sso.config_created"
    SSO_CONFIG_MODIFIED = "authn.sso.config_modified"
    SSO_CONFIG_DELETED = "authn.sso.config_deleted"
    LOCAL_AUTH_CONFIG_ENABLED = "authn.local_auth.config_enabled"
    LOCAL_AUTH_CONFIG_DISABLED = "authn.local_auth.config_disabled"
    
    # Authorization & Access
    PERMISSION_GRANT = "authz.permission.grant"
    PERMISSION_REVOKE = "authz.permission.revoke"
    ROLE_ASSIGN = "authz.role.assign"
    ROLE_UNASSIGN = "authz.role.unassign"
    GROUP_MEMBERSHIP_ADD = "authz.group_membership.add"
    GROUP_MEMBERSHIP_REMOVE = "authz.group_membership.remove"
    USER_STATUS_ENABLED = "authz.user.status_enabled"
    USER_STATUS_DISABLED = "authz.user.status_disabled"
    USER_STATUS_DELETED = "authz.user.status_deleted"
    USER_STATUS_LOCKED = "authz.user.status_locked"
    USER_STATUS_UNLOCKED = "authz.user.status_unlocked"
    IMPERSONATION_START = "authz.impersonation.start"
    IMPERSONATION_STOP = "authz.impersonation.stop"
    INVITE_SENT = "authz.invite.sent"
    INVITE_ACCEPTED = "authz.invite.accepted"
    INVITE_REVOKED = "authz.invite.revoked"
    INVITE_EXPIRED = "authz.invite.expired"
    
    # Customer Data Actions
    CUSTOMER_RECORD_VIEW = "data.customer.record.view"
    CUSTOMER_RECORD_MODIFY = "data.customer.record.modify"
    CUSTOMER_LIST_VIEW = "data.customer.list.view"
    CUSTOMER_LIST_MODIFY = "data.customer.list.modify"
    REPORT_EXPORT = "data.report.export"
    REPORT_DOWNLOAD = "data.report.download"
    
    # Key Configuration Changes
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    API_KEY_PERMISSIONS_MODIFIED = "api_key.permissions_modified"
    
    # API Endpoint Access
    API_REQUEST_SUCCESS = "api.request.success"
    API_REQUEST_FAILURE = "api.request.failure"

# Authentication protocols using standardized format
class AuthProtocol:
    API_KEY = "auth.protocol.api_key"
    OAUTH2_JWT = "auth.protocol.oauth2.jwt"
    OAUTH2_CLIENT_CREDENTIALS = "auth.protocol.oauth2.client_credentials"
    OAUTH2_AUTHORIZATION_CODE = "auth.protocol.oauth2.authorization_code"
    OAUTH2_IMPLICIT = "auth.protocol.oauth2.implicit"
    OAUTH2_PASSWORD_GRANT = "auth.protocol.oauth2.password_grant"
    SAML = "auth.protocol.saml"
    OIDC = "auth.protocol.oidc"
    SESSION_COOKIE = "auth.protocol.session_cookie"
    M2M_TOKEN = "auth.protocol.m2m_token"
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