"""
File: context_helpers.py

Python integration helpers for automatic security context extraction.
These helpers extract common fields from web framework requests and auth sessions.

Supports:
- Flask requests
- FastAPI/Starlette requests
- AWS Lambda events
- Generic WSGI/ASGI requests
"""

import hashlib
import os
import re
from typing import Any, Dict, List, Optional, TypedDict

from security_log_fields import CloudEnvType


class AuthSession(TypedDict, total=False):
    """Session data from authentication providers."""
    user: Optional[Dict[str, Any]]
    email: Optional[str]
    expires: Optional[str]
    session_token: Optional[str]
    id: Optional[str]


class SecurityContext(TypedDict, total=False):
    """
    Auto-extracted security context fields.
    
    Use `validate_security_context()` to ensure all required fields are present
    and get a `ValidatedSecurityContext` with non-optional fields.
    """
    # From Request Headers
    user_agent: Optional[str]
    source_ip_address: Optional[str]
    endpoint_path: Optional[str]
    http_method: Optional[str]
    
    # From Auth Session
    actor_identifier: Optional[str]
    session_id: Optional[str]
    
    # From Environment
    cloud_env_type: Optional[str]
    cloud_env_name: Optional[str]
    cloud_env_unique_id: Optional[str]
    service_name: Optional[str]
    service_account_id: Optional[str]




class SecurityContextOptions(TypedDict, total=False):
    """Options for creating security context."""
    service_name: Optional[str]
    cloud_env_type: Optional[str]
    cloud_env_name: Optional[str]
    cloud_env_unique_id: Optional[str]
    service_account_id: Optional[str]
    session_id: Optional[str]


# ============================================================================
# Request Header Extraction
# ============================================================================

def extract_user_agent(request: Any) -> Optional[str]:
    """
    Extract user agent string from request.
    
    Supports:
    - Flask request objects
    - FastAPI/Starlette request objects
    - AWS Lambda event dicts
    - Generic objects with headers dict/attribute
    
    Args:
        request: The incoming request object or event
        
    Returns:
        User agent string or None
    """
    try:
        # AWS Lambda event (API Gateway)
        if isinstance(request, dict):
            headers = request.get('headers', {}) or {}
            # API Gateway normalizes headers to lowercase
            return headers.get('user-agent') or headers.get('User-Agent')
        
        # Flask/Werkzeug request
        if hasattr(request, 'user_agent'):
            ua = request.user_agent
            if hasattr(ua, 'string'):
                return ua.string
            return str(ua) if ua else None
        
        # FastAPI/Starlette or generic request with headers
        if hasattr(request, 'headers'):
            headers = request.headers
            if hasattr(headers, 'get'):
                return headers.get('user-agent') or headers.get('User-Agent')
            elif isinstance(headers, dict):
                return headers.get('user-agent') or headers.get('User-Agent')
        
        return None
    except Exception:
        return None


def extract_source_ip(request: Any) -> Optional[str]:
    """
    Extract client IP address from request.
    
    Checks multiple sources in order of preference:
    1. x-forwarded-for (first IP in list)
    2. x-real-ip
    3. cf-connecting-ip (Cloudflare)
    4. Remote address (direct connection)
    
    Args:
        request: The incoming request object or event
        
    Returns:
        IP address string or None
    """
    try:
        headers = {}
        remote_addr = None
        
        # AWS Lambda event (API Gateway)
        if isinstance(request, dict):
            headers = request.get('headers', {}) or {}
            # API Gateway v2 format
            request_context = request.get('requestContext', {})
            if 'http' in request_context:
                remote_addr = request_context['http'].get('sourceIp')
            # API Gateway v1 format
            elif 'identity' in request_context:
                remote_addr = request_context['identity'].get('sourceIp')
        else:
            # Flask/Werkzeug request
            if hasattr(request, 'headers'):
                h = request.headers
                if hasattr(h, 'get'):
                    headers = {k.lower(): v for k, v in h.items()} if hasattr(h, 'items') else {}
                elif isinstance(h, dict):
                    headers = {k.lower(): v for k, v in h.items()}
            
            # Get remote address
            if hasattr(request, 'remote_addr'):
                remote_addr = request.remote_addr
            elif hasattr(request, 'client'):
                # FastAPI/Starlette
                client = request.client
                if client and hasattr(client, 'host'):
                    remote_addr = client.host
        
        # Normalize header keys
        headers = {k.lower(): v for k, v in headers.items()} if headers else {}
        
        # Try x-forwarded-for first
        forwarded = headers.get('x-forwarded-for')
        if forwarded:
            first_ip = forwarded.split(',')[0].strip()
            if first_ip and first_ip != 'unknown':
                return first_ip
        
        # Try x-real-ip
        real_ip = headers.get('x-real-ip')
        if real_ip and real_ip != 'unknown':
            return real_ip
        
        # Try Cloudflare header
        cf_ip = headers.get('cf-connecting-ip')
        if cf_ip and cf_ip != 'unknown':
            return cf_ip
        
        # Fall back to remote address
        if remote_addr and remote_addr != 'unknown':
            return remote_addr
        
        return None
    except Exception:
        return None


def extract_endpoint_path(request: Any) -> Optional[str]:
    """
    Extract endpoint path from request.
    
    Args:
        request: The incoming request object or event
        
    Returns:
        Endpoint path or None
    """
    try:
        # AWS Lambda event (API Gateway)
        if isinstance(request, dict):
            # API Gateway v2 format
            if 'rawPath' in request:
                return request['rawPath']
            # API Gateway v1 format
            if 'path' in request:
                return request['path']
            # Request context fallback
            request_context = request.get('requestContext', {})
            if 'http' in request_context:
                return request_context['http'].get('path')
            return request_context.get('path')
        
        # Flask/Werkzeug request
        if hasattr(request, 'path'):
            return request.path
        
        # FastAPI/Starlette request
        if hasattr(request, 'url'):
            url = request.url
            if hasattr(url, 'path'):
                return url.path
        
        return None
    except Exception:
        return None


def extract_http_method(request: Any) -> Optional[str]:
    """
    Extract HTTP method from request.
    
    Args:
        request: The incoming request object or event
        
    Returns:
        HTTP method or None
    """
    try:
        # AWS Lambda event (API Gateway)
        if isinstance(request, dict):
            # API Gateway v2 format
            request_context = request.get('requestContext', {})
            if 'http' in request_context:
                return request_context['http'].get('method')
            # API Gateway v1 format
            return request.get('httpMethod') or request_context.get('httpMethod')
        
        # Flask/Werkzeug or FastAPI/Starlette request
        if hasattr(request, 'method'):
            return request.method
        
        return None
    except Exception:
        return None


# ============================================================================
# Auth Session Extraction
# ============================================================================

def extract_actor_identifier(session: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Extract actor identifier (user email) from auth session.
    
    Args:
        session: The auth session dict
        
    Returns:
        User email or None
    """
    try:
        if not session:
            return None
        
        # Direct email field
        if 'email' in session:
            return session['email'] or None
        
        # Nested user object (next-auth style)
        user = session.get('user')
        if user and isinstance(user, dict):
            return user.get('email') or None
        
        # Cognito style
        if 'attributes' in session:
            return session['attributes'].get('email') or None
        
        return None
    except Exception:
        return None


def extract_session_id(session: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Generate a session ID from auth session data.
    
    Creates a deterministic session ID by hashing:
    - Session token (if available)
    - Or: user email + session expiry
    
    Args:
        session: The auth session dict
        
    Returns:
        Generated session ID or None
    """
    try:
        if not session:
            return None
        
        # If the session has an explicit ID
        if 'id' in session and session['id']:
            return session['id']
        
        if 'session_id' in session and session['session_id']:
            return session['session_id']
        
        # If there's a session token, hash it
        token = session.get('session_token') or session.get('sessionToken') or session.get('access_token')
        if token:
            hash_val = hashlib.sha256(token.encode()).hexdigest()[:16]
            return f"sess_{hash_val}"
        
        # Generate from user + expiry
        email = extract_actor_identifier(session)
        expires = session.get('expires') or session.get('exp')
        
        if email and expires:
            combined = f"{email}:{expires}"
            hash_val = hashlib.sha256(combined.encode()).hexdigest()[:16]
            return f"sess_{hash_val}"
        
        # If we have just email, create a time-based session
        if email:
            import time
            # Round to 15-minute windows to group related events
            time_window = int(time.time() / (15 * 60))
            combined = f"{email}:{time_window}"
            hash_val = hashlib.sha256(combined.encode()).hexdigest()[:16]
            return f"sess_{hash_val}"
        
        return None
    except Exception:
        return None


# ============================================================================
# Environment Extraction
# ============================================================================

def extract_cloud_env_type() -> Optional[str]:
    """
    Detect cloud environment type from environment variables.
    
    Checks common environment variables in order:
    1. CLOUD_ENV_TYPE (explicit)
    2. NEXT_PUBLIC_ENVIRONMENT_NAME
    3. ENVIRONMENT / ENV
    4. NODE_ENV
    5. AWS_LAMBDA_FUNCTION_NAME pattern
    
    Returns:
        CloudEnvType constant or None
    """
    try:
        # 1. Explicit CLOUD_ENV_TYPE
        explicit = os.environ.get('CLOUD_ENV_TYPE')
        if explicit:
            return _map_to_cloud_env_type(explicit)
        
        # 2. NEXT_PUBLIC_ENVIRONMENT_NAME (common in Next.js apps)
        next_env = os.environ.get('NEXT_PUBLIC_ENVIRONMENT_NAME')
        if next_env:
            return _map_to_cloud_env_type(next_env)
        
        # 3. ENVIRONMENT or ENV
        env = os.environ.get('ENVIRONMENT') or os.environ.get('ENV')
        if env:
            return _map_to_cloud_env_type(env)
        
        # 4. NODE_ENV (for Node.js apps running Python)
        node_env = os.environ.get('NODE_ENV')
        if node_env:
            return _map_to_cloud_env_type(node_env)
        
        # 5. Try to detect from Lambda function name
        lambda_name = os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
        if lambda_name:
            lambda_lower = lambda_name.lower()
            if '-prod' in lambda_lower or '_prod' in lambda_lower:
                return CloudEnvType.PROD
            if '-dev' in lambda_lower or '_dev' in lambda_lower:
                return CloudEnvType.DEV
            if '-stg' in lambda_lower or '_stg' in lambda_lower or '-staging' in lambda_lower:
                return CloudEnvType.STAGE
            if '-test' in lambda_lower or '_test' in lambda_lower:
                return CloudEnvType.TEST
        
        return None
    except Exception:
        return None


def _map_to_cloud_env_type(env: str) -> str:
    """Map environment string to CloudEnvType constant."""
    normalized = env.lower().strip()
    
    mapping = {
        'production': CloudEnvType.PROD,
        'prod': CloudEnvType.PROD,
        'prd': CloudEnvType.PROD,
        'staging': CloudEnvType.STAGE,
        'stage': CloudEnvType.STAGE,
        'stg': CloudEnvType.STAGE,
        'development': CloudEnvType.DEV,
        'dev': CloudEnvType.DEV,
        'test': CloudEnvType.TEST,
        'testing': CloudEnvType.TEST,
        'qa': CloudEnvType.TEST,
        'preview': CloudEnvType.STAGE,  # Treat preview as staging
    }
    
    if normalized in mapping:
        return mapping[normalized]
    
    # Return as-is if it already looks like a CloudEnvType constant
    if normalized.startswith('cloud.env.type.'):
        return env
    
    # Default to the raw value wrapped in our format
    return f"cloud.env.type.{normalized}"


def extract_cloud_env_name() -> Optional[str]:
    """
    Extract human-readable cloud environment name.
    
    Checks in order:
    1. CLOUD_ENV_NAME (explicit)
    2. NEXT_PUBLIC_ENVIRONMENT_NAME (common in Next.js apps)
    3. ENVIRONMENT / ENV
    4. NODE_ENV (formatted nicely)
    
    Returns:
        Human-readable environment name or None
    """
    try:
        # 1. Explicit CLOUD_ENV_NAME
        explicit = os.environ.get('CLOUD_ENV_NAME')
        if explicit:
            return explicit
        
        # 2. NEXT_PUBLIC_ENVIRONMENT_NAME (standard for Next.js apps)
        next_env = os.environ.get('NEXT_PUBLIC_ENVIRONMENT_NAME')
        if next_env:
            return next_env
        
        # 3. ENVIRONMENT or ENV
        env = os.environ.get('ENVIRONMENT') or os.environ.get('ENV')
        if env:
            return _format_env_name(env)
        
        # 4. NODE_ENV (formatted)
        node_env = os.environ.get('NODE_ENV')
        if node_env:
            return _format_env_name(node_env)
        
        return None
    except Exception:
        return None


def _format_env_name(env: str) -> str:
    """Format environment name to be human-readable."""
    normalized = env.lower().strip()
    
    name_map = {
        'production': 'Production',
        'prod': 'Production',
        'prd': 'Production',
        'staging': 'Staging',
        'stage': 'Staging',
        'stg': 'Staging',
        'development': 'Development',
        'dev': 'Development',
        'test': 'Test',
        'testing': 'Test',
        'qa': 'QA',
        'preview': 'Preview',
    }
    
    return name_map.get(normalized, env)


def extract_cloud_env_unique_id() -> Optional[str]:
    """
    Extract AWS Account ID / cloud environment unique ID.
    
    Checks in order:
    1. CLOUD_ENV_UNIQUE_ID (explicit)
    2. AWS_ACCOUNT_ID
    3. Parse from any ARN in common env vars
    
    Returns:
        AWS Account ID or None
    """
    try:
        # 1. Explicit
        explicit = os.environ.get('CLOUD_ENV_UNIQUE_ID')
        if explicit:
            return explicit
        
        # 2. AWS_ACCOUNT_ID
        account_id = os.environ.get('AWS_ACCOUNT_ID')
        if account_id:
            return account_id
        
        # 3. Try to parse from any ARN in common env vars
        arn_sources = [
            os.environ.get('AWS_EXECUTION_ROLE_ARN'),
            os.environ.get('AWS_LAMBDA_FUNCTION_ARN'),
            os.environ.get('SERVICE_ACCOUNT_ID'),
            os.environ.get('ROLE_ARN'),
        ]
        
        arn_pattern = re.compile(r'arn:aws:[^:]+:[^:]*:(\d{12}):')
        
        for arn in arn_sources:
            if arn:
                match = arn_pattern.search(arn)
                if match:
                    return match.group(1)
        
        return None
    except Exception:
        return None


def extract_service_name() -> Optional[str]:
    """
    Extract service name from environment.
    
    Checks in order:
    1. SERVICE_NAME (explicit)
    2. NEXT_PUBLIC_APP_NAME
    3. AWS_LAMBDA_FUNCTION_NAME (cleaned up)
    
    Returns:
        Service name or None
    """
    try:
        # 1. Explicit SERVICE_NAME
        explicit = os.environ.get('SERVICE_NAME')
        if explicit:
            return explicit
        
        # 2. NEXT_PUBLIC_APP_NAME
        app_name = os.environ.get('NEXT_PUBLIC_APP_NAME')
        if app_name:
            return app_name
        
        # 3. Lambda function name (clean it up)
        lambda_name = os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
        if lambda_name:
            # Remove common prefixes/suffixes like env names
            clean_name = re.sub(r'-(prod|dev|stg|staging|test)$', '', lambda_name, flags=re.IGNORECASE)
            clean_name = re.sub(r'^(prod|dev|stg|staging|test)-', '', clean_name, flags=re.IGNORECASE)
            return clean_name or lambda_name
        
        return None
    except Exception:
        return None


def extract_service_account_id() -> Optional[str]:
    """
    Extract service account ID (IAM role ARN, user ARN, etc.).
    
    Checks in order:
    1. SERVICE_ACCOUNT_ID (explicit)
    2. AWS_EXECUTION_ROLE_ARN (Lambda)
    3. AWS_ROLE_ARN / ROLE_ARN
    4. Construct from AWS_ACCESS_KEY_ID pattern (for IAM users)
    
    Returns:
        Service account ID/ARN or None
    """
    try:
        # 1. Explicit SERVICE_ACCOUNT_ID
        explicit = os.environ.get('SERVICE_ACCOUNT_ID')
        if explicit:
            return explicit
        
        # 2. Lambda execution role ARN
        execution_role = os.environ.get('AWS_EXECUTION_ROLE_ARN')
        if execution_role:
            return execution_role
        
        # 3. Generic role ARN
        role_arn = os.environ.get('AWS_ROLE_ARN') or os.environ.get('ROLE_ARN')
        if role_arn:
            return role_arn
        
        # 4. For IAM users, construct an identifier
        access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
        if access_key_id:
            if access_key_id.startswith('AKIA'):
                # IAM user
                return f"iam-user:{access_key_id[:8]}..."
            elif access_key_id.startswith('ASIA'):
                # Assumed role - temporary credentials
                session_name = os.environ.get('AWS_ROLE_SESSION_NAME')
                if session_name:
                    return f"assumed-role:{session_name}"
        
        return None
    except Exception:
        return None


# ============================================================================
# Main Context Creation Function
# ============================================================================

def create_security_context(
    request: Any = None,
    session: Optional[Dict[str, Any]] = None,
    options: Optional[SecurityContextOptions] = None
) -> SecurityContext:
    """
    Create a security context by auto-extracting fields from request and session.
    
    This function extracts all available fields from:
    - Request headers (user agent, IP, path, method)
    - Auth session (actor identifier, session ID)
    - Environment variables (cloud env type, account ID, service name, service account)
    
    Any fields that cannot be extracted will be None.
    You can override any auto-extracted field by passing explicit options.
    
    Args:
        request: The incoming request (Flask, FastAPI, Lambda event, etc.)
        session: The auth session dict
        options: Optional overrides and explicit values
        
    Returns:
        SecurityContext with auto-extracted fields
        
    Example:
        # In a Flask route
        from context_helpers import create_security_context
        from flask import request, session
        
        @app.route('/api/customers/<id>')
        def get_customer(id):
            context = create_security_context(request, session)
            
            log_record_access(
                **context,  # Spreads all auto-extracted fields
                
                # You still need to provide event-specific fields:
                event_type=EventType.RECORD_ACCESS,
                actor_type=ActorType.HUMAN_INTERNAL,  # Not auto-extracted
                status=Status.SUCCESS,
                data_sensitivity_level=DataSensitivityLevel.PII_BASIC,
                id_list=[id],
                detail=Detail.VIEW_RECORD
            )
    """
    opts = options or {}
    context: SecurityContext = {}
    
    # === Request-based extraction ===
    if request:
        context['user_agent'] = extract_user_agent(request)
        context['source_ip_address'] = extract_source_ip(request)
        context['endpoint_path'] = extract_endpoint_path(request)
        context['http_method'] = extract_http_method(request)
    
    # === Session-based extraction ===
    context['actor_identifier'] = extract_actor_identifier(session)
    context['session_id'] = opts.get('session_id') or extract_session_id(session)
    
    # === Environment-based extraction ===
    context['cloud_env_type'] = opts.get('cloud_env_type') or extract_cloud_env_type()
    context['cloud_env_name'] = opts.get('cloud_env_name') or extract_cloud_env_name()
    context['cloud_env_unique_id'] = opts.get('cloud_env_unique_id') or extract_cloud_env_unique_id()
    context['service_name'] = opts.get('service_name') or extract_service_name()
    context['service_account_id'] = opts.get('service_account_id') or extract_service_account_id()
    
    return context


def create_server_context(options: Optional[SecurityContextOptions] = None) -> SecurityContext:
    """
    Create security context for server-side operations without a request object.
    Useful for background jobs, cron tasks, or internal service calls.
    
    Args:
        options: Explicit values and overrides
        
    Returns:
        SecurityContext with environment-based fields only
        
    Example:
        # In a background job
        context = create_server_context({
            'service_name': 'cron-job-processor'
        })
        
        log_api_request(
            **context,
            event_type=EventType.API_REQUEST_PROCESSED,
            actor_type=ActorType.SYSTEM,
            actor_identifier='system:cron-scheduler',
            status=Status.SUCCESS
        )
    """
    return create_security_context(None, None, options)


def create_lambda_context(event: Dict[str, Any], context: Any = None) -> SecurityContext:
    """
    Create security context specifically for AWS Lambda handlers.
    
    Args:
        event: Lambda event (API Gateway, etc.)
        context: Lambda context object (optional, for extracting function info)
        
    Returns:
        SecurityContext with Lambda-specific extraction
        
    Example:
        def lambda_handler(event, context):
            sec_context = create_lambda_context(event, context)
            
            log_api_request(
                **sec_context,
                event_type=EventType.API_REQUEST_PROCESSED,
                actor_type=ActorType.SERVICE_INTERNAL,
                status=Status.SUCCESS
            )
    """
    # Extract session from Lambda event if present (e.g., from authorizer)
    session = None
    request_context = event.get('requestContext', {})
    
    # Try to get user info from authorizer
    authorizer = request_context.get('authorizer', {})
    if authorizer:
        # Lambda authorizer or Cognito
        claims = authorizer.get('claims', {}) or authorizer
        if claims:
            session = {
                'email': claims.get('email'),
                'user': {'email': claims.get('email')},
            }
    
    # Create context from Lambda event
    sec_context = create_security_context(event, session)
    
    # Add Lambda-specific context if available
    if context and hasattr(context, 'invoked_function_arn'):
        # Extract account ID from function ARN
        arn = context.invoked_function_arn
        arn_match = re.search(r'arn:aws:lambda:[^:]+:(\d{12}):', arn)
        if arn_match and not sec_context.get('cloud_env_unique_id'):
            sec_context['cloud_env_unique_id'] = arn_match.group(1)
    
    return sec_context


# ============================================================================
# Validation Helpers
# ============================================================================

# Required fields that must be present for security logging
REQUIRED_CONTEXT_FIELDS = [
    'actor_identifier',
    'session_id',
    'cloud_env_type',
    'cloud_env_name',
    'cloud_env_unique_id',
    'service_name',
    'service_account_id'
]


def get_missing_context_fields(context: SecurityContext) -> List[str]:
    """
    Check if a security context has all required base fields populated.
    Returns a list of missing fields.
    
    Args:
        context: The security context to validate
        
    Returns:
        List of missing field names (empty if all required fields are present)
    """
    return [field for field in REQUIRED_CONTEXT_FIELDS if not context.get(field)]


def diagnose_security_context(context: SecurityContext) -> Dict[str, Any]:
    """
    Check which fields could not be auto-extracted and provide suggestions.
    
    Use this during development to understand what environment variables
    need to be configured for full auto-extraction.
    
    Args:
        context: The security context to check
        
    Returns:
        Dict with:
            - has_missing: bool indicating if any fields are missing
            - missing_fields: list of field names that are missing
            - suggestions: list of dicts with field, env_var, and description
            
    Example:
        context = create_security_context(request, session)
        diagnostics = diagnose_security_context(context)
        
        if diagnostics['has_missing']:
            print('Missing fields and how to fix:')
            for s in diagnostics['suggestions']:
                print(f"  {s['field']}: set {s['env_var']}")
    """
    missing = get_missing_context_fields(context)
    
    env_var_map = {
        'actor_identifier': {'env_var': 'N/A - from auth session', 'description': 'Pass session with user email'},
        'session_id': {'env_var': 'N/A - derived from session', 'description': 'Pass session with user email and expires'},
        'cloud_env_type': {'env_var': 'CLOUD_ENV_TYPE or NEXT_PUBLIC_ENVIRONMENT_NAME', 'description': 'Environment type (prod, dev, etc.)'},
        'cloud_env_name': {'env_var': 'CLOUD_ENV_NAME or NEXT_PUBLIC_ENVIRONMENT_NAME', 'description': 'Human-readable environment name'},
        'cloud_env_unique_id': {'env_var': 'AWS_ACCOUNT_ID or CLOUD_ENV_UNIQUE_ID', 'description': 'AWS Account ID'},
        'service_name': {'env_var': 'SERVICE_NAME', 'description': 'Application/service name'},
        'service_account_id': {'env_var': 'SERVICE_ACCOUNT_ID or AWS_EXECUTION_ROLE_ARN', 'description': 'IAM role/user ARN'},
    }
    
    suggestions = []
    for field in missing:
        info = env_var_map.get(field, {'env_var': 'Unknown', 'description': 'Check documentation'})
        suggestions.append({
            'field': field,
            'env_var': info['env_var'],
            'description': info['description']
        })
    
    return {
        'has_missing': len(missing) > 0,
        'missing_fields': missing,
        'suggestions': suggestions
    }


def warn_missing_context_fields(
    context: SecurityContext,
    log_fn=None
) -> None:
    """
    Log warnings for any fields that couldn't be auto-extracted.
    Call this in development to help identify missing environment configuration.
    
    Args:
        context: The security context to check
        log_fn: Logging function (defaults to print with warning prefix)
    """
    if log_fn is None:
        import warnings
        log_fn = lambda msg: warnings.warn(msg, stacklevel=3)
    
    missing = get_missing_context_fields(context)
    
    if missing:
        log_fn(
            f"[Security Logging] Could not auto-extract fields: {', '.join(missing)}. "
            f"Set these explicitly or configure environment variables. "
            f"See documentation for required env vars."
        )

