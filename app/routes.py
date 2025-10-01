import base64
from flask import url_for, redirect, render_template, session, request, jsonify, current_app
from app import app, oauth
import jwt
import time
from cryptography.hazmat.primitives import serialization

@app.route('/')
def home():
    user = session.get('user')
    return render_template('home.html', user=user)

@app.route('/login')
def login():
    next_url = request.args.get('next')
    session['next_url'] = next_url
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    token = oauth.keycloak.authorize_access_token()
    user_info = token.get('userinfo')

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
    session.pop('user', None)
    keycloak_server_url = app.config.get("KEYCLOAK_SERVER_URL")
    post_logout_redirect_uri = url_for('home', _external=True)
    logout_url = f"{keycloak_server_url}/protocol/openid-connect/logout?post_logout_redirect_uri={post_logout_redirect_uri}"
    return redirect(logout_url)

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
