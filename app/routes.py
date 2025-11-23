import base64
import os
import requests
import json
from flask import url_for, redirect, render_template, session, request, jsonify, current_app, make_response
from app import app, oauth, limiter
from app.helm_logger import get_helm_logger
import jwt
import time
from cryptography.hazmat.primitives import serialization
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Health check library
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from health_check import HealthChecker


def get_user_homepage(user_email, token):
    """
    Get user's preferred home page from Codex with graceful fallback.

    Returns the service slug to redirect to (e.g., 'beacon', 'codex').
    Falls back through: user preference → beacon → first available service → helm
    """
    logger = get_helm_logger()
    codex_url = current_app.config.get('CODEX_SERVICE_URL', 'http://localhost:5010')
    verify_ssl = current_app.config.get('VERIFY_SSL', False)

    # Fallback order: beacon → knowledgetree → codex → helm
    fallback_order = ['beacon', 'knowledgetree', 'codex', 'helm']

    try:
        # Try to get user's preference from Codex
        response = requests.get(
            f"{codex_url}/api/public/user/home-page",
            params={'email': user_email},
            headers={'Authorization': f'Bearer {token}'},
            verify=verify_ssl,
            timeout=2
        )

        if response.status_code == 200:
            data = response.json()
            preferred_page = data.get('home_page', 'beacon')

            # Check if preferred service is available
            if is_service_available(preferred_page):
                if logger:
                    logger.info(f"Redirecting {user_email} to preferred home page: {preferred_page}")
                return preferred_page
            else:
                if logger:
                    logger.warning(f"Preferred page {preferred_page} not available, falling back")

    except Exception as e:
        if logger:
            logger.warning(f"Could not get home page preference from Codex: {e}")

    # Fallback: try services in order
    for service in fallback_order:
        if is_service_available(service):
            if logger:
                logger.info(f"Using fallback home page: {service}")
            return service

    # Ultimate fallback: helm (should always be available)
    if logger:
        logger.warning("All fallback services unavailable, defaulting to helm")
    return 'helm'


def is_service_available(service_slug):
    """
    Check if a service is available by checking if it's in the services config.

    Returns True if the service exists and is visible.
    """
    try:
        # Load services.json to check availability
        services_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'services.json')
        if not os.path.exists(services_file):
            # If no services.json, assume common services exist
            return service_slug in ['beacon', 'codex', 'helm']

        with open(services_file, 'r') as f:
            services = json.load(f)

        service_config = services.get(service_slug)
        if not service_config:
            return False

        # Check if service is visible (not an infrastructure service)
        return service_config.get('visible', True)

    except Exception:
        # If we can't check, assume beacon/codex/helm are available
        return service_slug in ['beacon', 'codex', 'helm']


@app.route('/')
def home():
    """
    Core service home page.

    Displays the Core service home page with user information if logged in.
    Sets no-cache headers to prevent back button issues after logout.

    Returns:
        Response: Rendered home.html template with cache control headers
    """
    user = session.get('user')
    logger = get_helm_logger()
    if logger and user:
        logger.info(f"User {user.get('preferred_username')} accessed home page")

    response = make_response(render_template('home.html', user=user))
    # Prevent caching to avoid back button issues after logout
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/login')
@limiter.limit("10 per minute")  # Prevent login spam
def login():
    """
    Initiate OAuth2 login flow with Keycloak.

    Redirects the user to Keycloak for authentication. After successful authentication,
    Keycloak will redirect back to the /auth endpoint.

    Query Parameters:
        next (str, optional): URL to redirect to after successful login

    Returns:
        Response: Redirect to Keycloak authorization endpoint
    """
    logger = get_helm_logger()
    next_url = request.args.get('next')
    session['next_url'] = next_url
    if logger:
        logger.info(f"Login initiated, redirect to: {next_url or 'default'}")
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth')
@limiter.limit("20 per minute")  # Prevent auth callback abuse
def auth():
    """
    OAuth2 callback endpoint from Keycloak.

    Handles the authorization callback from Keycloak after user authentication.
    Exchanges the authorization code for access tokens, determines user permissions,
    creates a HiveMatrix JWT, and redirects to the requested page or home.

    Permission Levels (based on Keycloak groups):
        - admin: Members of 'admins' group
        - technician: Members of 'technicians' group
        - billing: Members of 'billing' group
        - client: Default for all other users

    Query Parameters:
        code (str): Authorization code from Keycloak (handled by OAuth library)
        error (str, optional): Error code if authentication failed

    Returns:
        Response: Redirect to next_url with JWT token, or to home page
    """
    logger = get_helm_logger()

    # Check for errors from Keycloak
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        if logger:
            logger.warning(f"Authentication error: {error} - {error_description}")

        # Clear any stale session data
        session.clear()

        # Redirect to login to try again
        return redirect(url_for('login', next=session.get('next_url')))

    try:
        token = oauth.keycloak.authorize_access_token()
    except Exception as e:
        if logger:
            logger.error(f"Failed to get access token: {e}")

        # Clear session and redirect to login
        session.clear()
        return redirect(url_for('login', next=session.get('next_url')))

    user_info = token.get('userinfo')

    if logger:
        logger.info(f"User authenticated: {user_info.get('preferred_username')}")

    # Store tokens for logout
    session['id_token'] = token.get('id_token')
    session['refresh_token'] = token.get('refresh_token')
    session['access_token'] = token.get('access_token')

    # --- Determine permission level from Keycloak groups ---
    # Permission levels control access across all HiveMatrix services
    # Hierarchy: admin > technician > billing > client
    # Groups can be in format 'groupname' or '/groupname' depending on Keycloak config
    groups = user_info.get('groups', [])

    # Check group membership for permission level (order matters - highest first)
    if 'admins' in groups or '/admins' in groups:
        permission_level = 'admin'  # Full system access
    elif 'technicians' in groups or '/technicians' in groups:
        permission_level = 'technician'  # Technical operations access
    elif 'billing' in groups or '/billing' in groups:
        permission_level = 'billing'  # Financial operations access
    else:
        permission_level = 'client'  # Limited access (default)

    private_key = current_app.config['JWT_PRIVATE_KEY']

    payload = {
        'iss': current_app.config['JWT_ISSUER'],
        'sub': user_info['sub'],
        'name': user_info['name'],
        'email': user_info['email'],
        'preferred_username': user_info['preferred_username'],
        'permission_level': permission_level,
        'groups': groups,  # Include groups in JWT for reference
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,
    }

    headers = {
        "kid": "hivematrix-signing-key-1"
    }

    hivematrix_token = jwt.encode(
        payload,
        private_key,
        algorithm=current_app.config['JWT_ALGORITHM'],
        headers=headers
    )

    next_url = session.pop('next_url', None)
    if next_url:
        return redirect(f"{next_url}?token={hivematrix_token}")

    # Get user's home page preference from Codex
    home_page = get_user_homepage(user_info.get('email'), hivematrix_token)

    session['user'] = user_info

    # Redirect to preferred home page with token
    nexus_url = app.config.get('NEXUS_SERVICE_URL', 'https://localhost')
    return redirect(f"{nexus_url}/{home_page}/?token={hivematrix_token}")

@app.route('/logout')
def logout():
    import requests
    logger = get_helm_logger()

    # Get tokens and user before clearing session
    refresh_token = session.get('refresh_token')
    access_token = session.get('access_token')
    user = session.get('user')

    if logger and user:
        logger.info(f"User {user.get('preferred_username')} logging out")

    keycloak_server_url = app.config.get("KEYCLOAK_SERVER_URL")
    client_id = app.config.get("KEYCLOAK_CLIENT_ID")
    client_secret = app.config.get("KEYCLOAK_CLIENT_SECRET")

    # Revoke both tokens to fully invalidate the session
    tokens_to_revoke = []
    if refresh_token:
        tokens_to_revoke.append(('refresh_token', refresh_token))
    if access_token:
        tokens_to_revoke.append(('access_token', access_token))

    for token_type, token in tokens_to_revoke:
        try:
            revoke_url = f"{keycloak_server_url}/protocol/openid-connect/revoke"

            response = requests.post(
                revoke_url,
                data={
                    'token': token,
                    'token_type_hint': token_type,
                    'client_id': client_id,
                    'client_secret': client_secret
                },
                verify=current_app.config.get('VERIFY_SSL', True),  # Configurable SSL verification
                timeout=5
            )

            if logger:
                if response.status_code == 200:
                    logger.info(f"{token_type} revoked successfully")
                else:
                    logger.warning(f"{token_type} revocation returned status {response.status_code}: {response.text}")
        except Exception as e:
            if logger:
                logger.error(f"Error revoking {token_type}: {e}")

    # Get redirect URL from query parameter, default to home
    redirect_url = request.args.get('redirect', url_for('home'))

    # Get id_token before clearing session
    id_token = session.get('id_token')

    # Clear Flask session
    session.clear()

    # If we have an id_token, redirect to Keycloak logout which will then redirect to our target
    if id_token:
        from urllib.parse import quote
        keycloak_realm = app.config.get("KEYCLOAK_REALM", "hivematrix")
        logout_url = f"{keycloak_server_url}/realms/{keycloak_realm}/protocol/openid-connect/logout"
        logout_redirect = f"{logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={quote(redirect_url)}"

        response = make_response(redirect(logout_redirect))
    else:
        # No id_token, just redirect directly
        if logger:
            logger.warning("No id_token found, skipping Keycloak logout")
        response = make_response(redirect(redirect_url))

    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    # Explicitly delete the session cookie
    response.set_cookie('session', '', expires=0, max_age=0, path='/')

    return response

@app.route('/service-token', methods=['POST'])
@limiter.exempt  # Internal service-to-service endpoint, protected by token caching
def service_token():
    """
    Generate a service-to-service authentication token.

    Creates a short-lived JWT (5 minutes) for service-to-service communication.
    These tokens allow services to call each other's APIs without user context.

    Request JSON Body:
        calling_service (str): Name of the service requesting the token
        target_service (str): Name of the service being called

    Returns:
        JSON: {'token': '<jwt_token>'} with 200 status
        JSON: {'error': '<message>'} with 400 status if parameters missing

    Example:
        POST /service-token
        {
            "calling_service": "codex",
            "target_service": "ledger"
        }

        Response:
        {
            "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        }
    """
    import re
    import json
    from pathlib import Path

    logger = get_helm_logger()

    data = request.get_json()
    calling_service = data.get('calling_service')
    target_service = data.get('target_service')

    if not calling_service or not target_service:
        return jsonify({'error': 'calling_service and target_service are required'}), 400

    # Input validation: prevent injection attacks and DoS
    # Service names must be alphanumeric with hyphens/underscores only, 1-50 chars
    service_name_pattern = re.compile(r'^[a-z0-9_-]{1,50}$')

    if not service_name_pattern.match(calling_service):
        if logger:
            logger.warning(f"Invalid calling_service format: {calling_service[:100]}")
        return jsonify({'error': 'Invalid calling_service format'}), 400

    if not service_name_pattern.match(target_service):
        if logger:
            logger.warning(f"Invalid target_service format: {target_service[:100]}")
        return jsonify({'error': 'Invalid target_service format'}), 400

    # Validate against known services list (if available)
    services_file = Path(__file__).parent.parent / 'services.json'
    if services_file.exists():
        try:
            with open(services_file, 'r') as f:
                known_services = json.load(f)

            if calling_service not in known_services:
                if logger:
                    logger.warning(f"Unknown calling_service: {calling_service}")
                return jsonify({'error': 'Unknown calling_service'}), 400

            if target_service not in known_services:
                if logger:
                    logger.warning(f"Unknown target_service: {target_service}")
                return jsonify({'error': 'Unknown target_service'}), 400
        except Exception as e:
            # If we can't read services.json, log but continue with format validation only
            if logger:
                logger.warning(f"Could not validate against services.json: {e}")

    # Validation passed
    
    private_key = current_app.config['JWT_PRIVATE_KEY']

    # JWT payload for service-to-service token
    # iss: Issuer (who created this token)
    # sub: Subject (what this token represents)
    # calling_service: Which service is making the call
    # target_service: Which service is being called
    # token_type: 'service' distinguishes from user tokens
    # iat: Issued at timestamp
    # exp: Expiration (5 minutes from now)
    payload = {
        'iss': current_app.config['JWT_ISSUER'],
        'sub': f'service:{calling_service}',
        'calling_service': calling_service,
        'target_service': target_service,
        'type': 'service',
        'iat': int(time.time()),
        'exp': int(time.time()) + 300,  # 5 minutes
    }
    
    headers = {
        "kid": "hivematrix-signing-key-1"
    }
    
    token = jwt.encode(
        payload,
        private_key,
        algorithm=current_app.config['JWT_ALGORITHM'],
        headers=headers
    )
    
    return jsonify({'token': token}), 200

@app.route('/api/token/exchange', methods=['POST'])
@limiter.limit("20 per minute")  # Prevent token exchange brute force
def token_exchange():
    """Exchange a Keycloak access token for a HiveMatrix JWT.

    This allows Nexus to handle OAuth flow and request JWT from Core.
    ---
    tags:
      - Authentication
    summary: Exchange Keycloak token for HiveMatrix JWT
    description: |
      Validates a Keycloak OAuth2 access token and returns a HiveMatrix JWT for service access.
      Used by Nexus after successful OAuth login to get a session token.

      Permission levels are determined by Keycloak groups:
      - admins → admin
      - technicians → technician
      - billing → billing
      - default → client
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - access_token
          properties:
            access_token:
              type: string
              description: Keycloak OAuth2 access token
              example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    responses:
      200:
        description: JWT token generated successfully
        schema:
          type: object
          properties:
            jwt:
              type: string
              description: HiveMatrix JWT token (valid for 1 hour)
              example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
            user:
              type: object
              properties:
                username:
                  type: string
                  example: "admin"
                email:
                  type: string
                  example: "admin@example.com"
                permission_level:
                  type: string
                  enum: [admin, technician, billing, client]
                  example: "admin"
      400:
        description: No access token provided
      401:
        description: Invalid access token
      500:
        description: Internal server error
    """
    logger = get_helm_logger()

    # Get the Keycloak access token from the request
    data = request.get_json() or {}
    access_token = data.get('access_token')

    if not access_token:
        # Try to get from Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            access_token = auth_header[7:]

    if not access_token:
        return jsonify({'error': 'No access token provided'}), 400

    # Verify the access token with Keycloak and get user info
    # Use Nexus URL for consistency with token issuer
    nexus_url = app.config.get("NEXUS_SERVICE_URL", "https://localhost")
    keycloak_realm = os.environ.get('KEYCLOAK_REALM', 'hivematrix')

    try:
        # Get user info from Keycloak through Nexus proxy
        # This ensures the token issuer matches what Keycloak expects
        userinfo_url = f"{nexus_url}/keycloak/realms/{keycloak_realm}/protocol/openid-connect/userinfo"
        user_response = requests.get(
            userinfo_url,
            headers={'Authorization': f'Bearer {access_token}'},
            verify=current_app.config.get('VERIFY_SSL', True),  # Configurable SSL verification
            timeout=10
        )

        if user_response.status_code != 200:
            if logger:
                logger.error(f"Failed to get user info from Keycloak: {user_response.status_code}")
            return jsonify({'error': 'Invalid access token'}), 401

        user_info = user_response.json()

        # Determine permission level from groups
        groups = user_info.get('groups', [])

        if 'admins' in groups or '/admins' in groups:
            permission_level = 'admin'
        elif 'technicians' in groups or '/technicians' in groups:
            permission_level = 'technician'
        elif 'billing' in groups or '/billing' in groups:
            permission_level = 'billing'
        else:
            permission_level = 'client'

        # Create a session for this user
        session_manager = current_app.config['SESSION_MANAGER']
        user_session_data = {
            'sub': user_info['sub'],
            'name': user_info.get('name', ''),
            'email': user_info.get('email', ''),
            'preferred_username': user_info.get('preferred_username', ''),
            'permission_level': permission_level,
            'groups': groups
        }
        session_id = session_manager.create_session(user_session_data)

        # Generate HiveMatrix JWT with session ID
        private_key = current_app.config['JWT_PRIVATE_KEY']

        payload = {
            'iss': current_app.config['JWT_ISSUER'],
            'sub': user_info['sub'],
            'jti': session_id,  # JWT ID - used for session revocation
            'name': user_info.get('name', ''),
            'email': user_info.get('email', ''),
            'preferred_username': user_info.get('preferred_username', ''),
            'permission_level': permission_level,
            'groups': groups,
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
        }

        headers = {
            "kid": "hivematrix-signing-key-1"
        }

        hivematrix_token = jwt.encode(
            payload,
            private_key,
            algorithm=current_app.config['JWT_ALGORITHM'],
            headers=headers
        )

        if logger:
            logger.info(f"Issued JWT for user {user_info.get('preferred_username')}")

        return jsonify({'token': hivematrix_token}), 200

    except Exception as e:
        if logger:
            logger.error(f"Token exchange error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/token/validate', methods=['POST'])
@limiter.exempt  # Internal validation endpoint, called frequently by services
def token_validate():
    """Validate that a token's session is still active.

    Returns user data if valid, error if revoked or expired.
    ---
    tags:
      - Authentication
    summary: Validate JWT token and check session status
    description: |
      Verifies JWT signature, expiration, and checks if the session has been revoked.
      Called by Nexus on every request to ensure the user's session is still active.

      This endpoint checks:
      1. JWT signature validity
      2. Token expiration
      3. Session revocation status (logout)
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            token:
              type: string
              description: HiveMatrix JWT token to validate
              example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    responses:
      200:
        description: Token is valid and session is active
        schema:
          type: object
          properties:
            valid:
              type: boolean
              example: true
            user:
              type: object
              properties:
                sub:
                  type: string
                  example: "user-uuid-1234"
                username:
                  type: string
                  example: "admin"
                email:
                  type: string
                  example: "admin@example.com"
                permission_level:
                  type: string
                  example: "admin"
      400:
        description: No token provided
      401:
        description: Token invalid, expired, or session revoked
        schema:
          type: object
          properties:
            valid:
              type: boolean
              example: false
            error:
              type: string
              example: "Session has been revoked"
    """
    logger = get_helm_logger()

    # Get token from request
    data = request.get_json() or {}
    token = data.get('token')

    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

    if not token:
        return jsonify({'error': 'No token provided', 'valid': False}), 400

    try:
        # Decode token to get session_id (jti)
        public_key = current_app.config['JWT_PUBLIC_KEY']
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[current_app.config['JWT_ALGORITHM']],
            options={"verify_exp": True}
        )

        session_id = payload.get('jti')
        if not session_id:
            return jsonify({'error': 'Token has no session ID', 'valid': False}), 401

        # Check if session is still valid
        session_manager = current_app.config['SESSION_MANAGER']
        session_data = session_manager.validate_session(session_id)

        if not session_data:
            if logger:
                logger.info(f"Session {session_id} invalid or revoked")
            return jsonify({'error': 'Session expired or revoked', 'valid': False}), 401

        return jsonify({'valid': True, 'user': session_data}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired', 'valid': False}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}', 'valid': False}), 401
    except Exception as e:
        if logger:
            logger.error(f"Token validation error: {e}")
        return jsonify({'error': 'Internal server error', 'valid': False}), 500


@app.route('/api/token/revoke', methods=['POST'])
def token_revoke():
    """Revoke a token's session (logout).
    ---
    tags:
      - Authentication
    summary: Revoke JWT token session (logout)
    description: |
      Revokes the session associated with a JWT token, effectively logging the user out.
      After revocation, the token will fail validation even if not yet expired.

      Used by Nexus when user clicks logout.
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            token:
              type: string
              description: HiveMatrix JWT token to revoke
              example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    responses:
      200:
        description: Session revoked successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Session revoked successfully"
      400:
        description: No token provided
      401:
        description: Invalid token
      500:
        description: Internal server error
    """
    logger = get_helm_logger()

    # Get token from request
    data = request.get_json() or {}
    token = data.get('token')

    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

    if not token:
        return jsonify({'error': 'No token provided'}), 400

    try:
        # Decode token to get session_id (jti)
        public_key = current_app.config['JWT_PUBLIC_KEY']
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[current_app.config['JWT_ALGORITHM']],
            options={"verify_exp": False}  # Allow revoking expired tokens
        )

        session_id = payload.get('jti')
        if not session_id:
            return jsonify({'error': 'Token has no session ID'}), 400

        # Revoke the session
        session_manager = current_app.config['SESSION_MANAGER']
        revoked = session_manager.revoke_session(session_id)

        if revoked:
            if logger:
                logger.info(f"Session {session_id} revoked by user {payload.get('preferred_username')}")
            return jsonify({'message': 'Session revoked successfully'}), 200
        else:
            return jsonify({'message': 'Session not found or already revoked'}), 404

    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401
    except Exception as e:
        if logger:
            logger.error(f"Token revocation error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/health')
@limiter.exempt
def health():
    """
    Comprehensive health check endpoint.

    Checks:
    - Redis connectivity (session storage)
    - Disk space
    - Keycloak availability

    Returns:
        JSON: Detailed health status with HTTP 200 (healthy) or 503 (unhealthy/degraded)
    """
    # Get Redis client if available
    redis_client = None
    try:
        from app import redis_client as app_redis
        redis_client = app_redis
    except:
        pass

    # Initialize health checker
    # Note: Not checking Keycloak as dependency since it doesn't have a standard /health endpoint
    # Keycloak availability is checked during actual authentication, not health checks
    health_checker = HealthChecker(
        service_name='core',
        redis_client=redis_client
    )

    return health_checker.get_health()

@app.route('/.well-known/jwks.json')
@limiter.exempt
def jwks():
    """
    JSON Web Key Set (JWKS) endpoint.

    Publishes Core's public RSA key in JWKS format for JWT signature verification.
    Other services fetch this on startup to verify HiveMatrix JWT tokens.

    Standard JWKS endpoint following RFC 7517.
    No authentication required - public key is public information.

    Returns:
        JSON: JWKS formatted response with RSA public key components (n, e)

    Example Response:
        {
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "kid": "hivematrix-signing-key-1",
                "use": "sig",
                "n": "0vx7agoebGcQ...",  # RSA modulus (base64url encoded)
                "e": "AQAB"  # RSA exponent (base64url encoded)
            }]
        }
    """
    public_key = current_app.config['JWT_PUBLIC_KEY']
    public_key_obj = serialization.load_pem_public_key(public_key)
    public_numbers = public_key_obj.public_numbers()

    def int_to_base64url(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')

    jwk = {
        "kty": "RSA",
        "alg": current_app.config['JWT_ALGORITHM'],
        "kid": "hivematrix-signing-key-1",
        "use": "sig",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }

    return jsonify({"keys": [jwk]})
