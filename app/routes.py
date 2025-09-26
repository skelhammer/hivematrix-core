from flask import url_for, redirect, render_template, session
from app import app, oauth

@app.route('/')
def home():
    # Check if user information is in the session
    user = session.get('user')
    return render_template('home.html', user=user)

@app.route('/login')
def login():
    # This is the entry point for authentication.
    # It redirects the user to Keycloak's login page.
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    # This is the callback route that Keycloak redirects to after a successful login.
    # We exchange the authorization code for an access token.
    token = oauth.keycloak.authorize_access_token()
    # The user's info is inside the token
    session['user'] = token.get('userinfo')
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    # Clear the local session
    session.pop('user', None)

    # Construct the Keycloak logout URL to invalidate the Keycloak session as well
    keycloak_server_url = app.config.get("KEYCLOAK_SERVER_URL")
    # This ensures the user is logged out of Keycloak and then redirected back to our app's home page.
    post_logout_redirect_uri = url_for('home', _external=True)
    logout_url = f"{keycloak_server_url}/protocol/openid-connect/logout?post_logout_redirect_uri={post_logout_redirect_uri}"

    return redirect(logout_url)

