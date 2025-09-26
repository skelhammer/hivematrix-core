import os
from flask import Flask
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
# Load configuration from .flaskenv
app.config.from_mapping(
    SECRET_KEY=os.environ.get("SECRET_KEY"),
    KEYCLOAK_CLIENT_SECRET=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
    KEYCLOAK_SERVER_URL=os.environ.get("KEYCLOAK_SERVER_URL"),
    KEYCLOAK_CLIENT_ID=os.environ.get("KEYCLOAK_CLIENT_ID"),
)

# Initialize Authlib OAuth client
oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=app.config.get("KEYCLOAK_CLIENT_ID"),
    client_secret=app.config.get("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=f'{app.config.get("KEYCLOAK_SERVER_URL")}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile' # Defines what info we want from Keycloak
    }
)

# Import routes after app and oauth are initialized
from app import routes

