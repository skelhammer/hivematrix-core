from flask import Flask
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)

# --- Explicitly load all required configuration from environment variables ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Keycloak Settings
app.config['KEYCLOAK_SERVER_URL'] = os.environ.get('KEYCLOAK_SERVER_URL')
app.config['KEYCLOAK_CLIENT_ID'] = os.environ.get('KEYCLOAK_CLIENT_ID')
app.config['KEYCLOAK_CLIENT_SECRET'] = os.environ.get('KEYCLOAK_CLIENT_SECRET')

# JWT Settings
app.config['JWT_PRIVATE_KEY_FILE'] = os.environ.get('JWT_PRIVATE_KEY_FILE')
app.config['JWT_PUBLIC_KEY_FILE'] = os.environ.get('JWT_PUBLIC_KEY_FILE')
app.config['JWT_ISSUER'] = os.environ.get('JWT_ISSUER')
app.config['JWT_ALGORITHM'] = os.environ.get('JWT_ALGORITHM')
# --- End of explicit configuration loading ---

# Validate that the secret key was loaded
if not app.config['SECRET_KEY']:
    raise ValueError("A SECRET_KEY must be set in the .flaskenv file.")

# Load JWT keys from files into config
try:
    with open(app.config['JWT_PRIVATE_KEY_FILE'], 'rb') as f:
        app.config['JWT_PRIVATE_KEY'] = f.read()
    with open(app.config['JWT_PUBLIC_KEY_FILE'], 'rb') as f:
        app.config['JWT_PUBLIC_KEY'] = f.read()
except (KeyError, TypeError):
    print("WARNING: JWT_PRIVATE_KEY_FILE or JWT_PUBLIC_KEY_FILE not configured in .flaskenv")
except FileNotFoundError:
    print("FATAL: JWT Key files not found. Please generate them using 'openssl'.")


oauth = OAuth(app)

# Load Keycloak realm from environment
keycloak_realm = os.environ.get('KEYCLOAK_REALM', 'hivematrix')
keycloak_server_url = app.config.get("KEYCLOAK_SERVER_URL")

oauth.register(
    name='keycloak',
    client_id=app.config.get("KEYCLOAK_CLIENT_ID"),
    client_secret=app.config.get("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=f'{keycloak_server_url}/realms/{keycloak_realm}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

from app import routes
