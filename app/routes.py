import base64
import os
import requests
from flask import url_for, redirect, render_template, session, request, jsonify, current_app, make_response
from app import app, oauth
from app.helm_logger import get_helm_logger
import jwt
import time
from cryptography.hazmat.primitives import serialization
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@app.route('/')
def home():
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
def login():
    logger = get_helm_logger()
    next_url = request.args.get('next')
    session['next_url'] = next_url
    if logger:
        logger.info(f"Login initiated, redirect to: {next_url or 'default'}")
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
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
    groups = user_info.get('groups', [])

    # Check group membership for permission level
    if 'admins' in groups or '/admins' in groups:
        permission_level = 'admin'
    elif 'technicians' in groups or '/technicians' in groups:
        permission_level = 'technician'
    elif 'billing' in groups or '/billing' in groups:
        permission_level = 'billing'
    else:
        permission_level = 'client'

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

    session['user'] = user_info
    return redirect(url_for('home'))

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
def service_token():
    data = request.get_json()
    calling_service = data.get('calling_service')
    target_service = data.get('target_service')
    
    if not calling_service or not target_service:
        return jsonify({'error': 'calling_service and target_service are required'}), 400
    
    private_key = current_app.config['JWT_PRIVATE_KEY']
    
    payload = {
        'iss': current_app.config['JWT_ISSUER'],
        'sub': f'service:{calling_service}',
        'calling_service': calling_service,
        'target_service': target_service,
        'type': 'service',
        'iat': int(time.time()),
        'exp': int(time.time()) + 300,
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
def token_exchange():
    """
    Exchange a Keycloak access token for a HiveMatrix JWT.
    This allows Nexus to handle OAuth flow and request JWT from Core.
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
            verify=False  # Accept self-signed cert for local dev
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

        # Generate HiveMatrix JWT
        private_key = current_app.config['JWT_PRIVATE_KEY']

        payload = {
            'iss': current_app.config['JWT_ISSUER'],
            'sub': user_info['sub'],
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
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "core"}), 200

@app.route('/.well-known/jwks.json')
def jwks():
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
