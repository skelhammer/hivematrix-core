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
    # Store the 'next' URL from query param to redirect after login
    next_url = request.args.get('next')
    session['next_url'] = next_url

    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    token = oauth.keycloak.authorize_access_token()
    user_info = token.get('userinfo')

    # --- Create our own HiveMatrix JWT ---
    private_key = current_app.config['JWT_PRIVATE_KEY']

    payload = {
        'iss': current_app.config['JWT_ISSUER'],
        'sub': user_info['sub'],
        'name': user_info['name'],
        'email': user_info['email'],
        'preferred_username': user_info['preferred_username'],
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600, # Expires in 1 hour
    }

    # **THE FIX IS HERE:** We add a header with the Key ID ('kid')
    # This ID must match the 'kid' served by our jwks.json endpoint.
    headers = {
        "kid": "hivematrix-signing-key-1"
    }

    hivematrix_token = jwt.encode(
        payload,
        private_key,
        algorithm=current_app.config['JWT_ALGORITHM'],
        headers=headers
    )

    # Redirect back to the service that initiated login (e.g., Nexus)
    next_url = session.pop('next_url', None)
    if next_url:
        # Pass our new token back to the client app
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

@app.route('/.well-known/jwks.json')
def jwks():
    """
    Exposes the public key in JWKS format for other services to verify tokens.
    """
    public_key = current_app.config['JWT_PUBLIC_KEY']

    # Load the PEM public key
    public_key_obj = serialization.load_pem_public_key(public_key)
    public_numbers = public_key_obj.public_numbers()

    # Helper to encode numbers to Base64URL format
    def int_to_base64url(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')

    jwk = {
        "kty": "RSA",
        "alg": current_app.config['JWT_ALGORITHM'],
        "kid": "hivematrix-signing-key-1", # Key ID
        "use": "sig", # Signature
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }

    return jsonify({"keys": [jwk]})
