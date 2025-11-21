from flask import Flask
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

app = Flask(__name__)

# Initialize rate limiter to prevent brute force and DoS attacks
# Uses remote address as key (X-Forwarded-For header trusted via ProxyFix)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # For production, use Redis: "redis://localhost:6379"
)

# Configure logging level from environment
import logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
app.logger.setLevel(getattr(logging, log_level, logging.INFO))

# --- Explicitly load all required configuration from environment variables ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Session configuration
# NOTE: These settings apply to Flask's session cookie (used for OAuth flow)
# HiveMatrix JWT tokens have separate expiration (configured in routes.py)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access (XSS protection)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Keycloak Settings
app.config['KEYCLOAK_SERVER_URL'] = os.environ.get('KEYCLOAK_SERVER_URL')
app.config['KEYCLOAK_CLIENT_ID'] = os.environ.get('KEYCLOAK_CLIENT_ID')
app.config['KEYCLOAK_CLIENT_SECRET'] = os.environ.get('KEYCLOAK_CLIENT_SECRET')

# JWT Settings
app.config['JWT_PRIVATE_KEY_FILE'] = os.environ.get('JWT_PRIVATE_KEY_FILE')
app.config['JWT_PUBLIC_KEY_FILE'] = os.environ.get('JWT_PUBLIC_KEY_FILE')
app.config['JWT_ISSUER'] = os.environ.get('JWT_ISSUER')
app.config['JWT_ALGORITHM'] = os.environ.get('JWT_ALGORITHM')

# SSL Verification Settings
# In development: Allow self-signed certificates (verify=False)
# In production: Always verify SSL certificates (verify=True)
# Default to False for local development (self-signed certs are common)
environment = os.environ.get('ENVIRONMENT', 'development')
app.config['VERIFY_SSL'] = (environment == 'production')
# --- End of explicit configuration loading ---

# Validate that the secret key was loaded
if not app.config['SECRET_KEY']:
    raise ValueError("A SECRET_KEY must be set in the .flaskenv file.")

# Load JWT RSA keys from files into config
# These keys are used for signing and verifying HiveMatrix JWT tokens
# Private key: Used by Core to sign tokens
# Public key: Used by all services to verify tokens (published via /.well-known/jwks.json)
try:
    with open(app.config['JWT_PRIVATE_KEY_FILE'], 'rb') as f:
        app.config['JWT_PRIVATE_KEY'] = f.read()
    with open(app.config['JWT_PUBLIC_KEY_FILE'], 'rb') as f:
        app.config['JWT_PUBLIC_KEY'] = f.read()
except (KeyError, TypeError):
    import logging
    logging.warning("JWT_PRIVATE_KEY_FILE or JWT_PUBLIC_KEY_FILE not configured in .flaskenv")
except FileNotFoundError:
    import logging
    logging.error("FATAL: JWT Key files not found. Please generate them using 'openssl'.")


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

# Initialize Helm logger for centralized logging
app.config['SERVICE_NAME'] = os.environ.get('SERVICE_NAME', 'core')
app.config['HELM_SERVICE_URL'] = os.environ.get('HELM_SERVICE_URL', 'http://localhost:5004')

from app.helm_logger import init_helm_logger
helm_logger = init_helm_logger(
    app.config['SERVICE_NAME'],
    app.config['HELM_SERVICE_URL']
)

# Initialize session manager for revokable tokens
# This allows Core to track active sessions and revoke JWTs (logout)
# Sessions are stored in-memory (for production, use Redis or database)
from app.session_manager import SessionManager
session_manager = SessionManager(max_session_lifetime=3600)  # 1 hour sessions
app.config['SESSION_MANAGER'] = session_manager

from app.version import VERSION, SERVICE_NAME as VERSION_SERVICE_NAME

# Context processor to inject version into all templates
@app.context_processor
def inject_version() -> dict:
    """
    Inject version information into all Jinja2 templates.

    This context processor makes app_version and app_service_name
    available to all templates without explicitly passing them.

    Returns:
        dict: Dictionary with 'app_version' and 'app_service_name' keys
    """
    return {
        'app_version': VERSION,
        'app_service_name': VERSION_SERVICE_NAME
    }

from app import routes

# Log service startup
helm_logger.info(f"{app.config['SERVICE_NAME']} service started")
