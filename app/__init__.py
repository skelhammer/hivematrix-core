from flask import Flask
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
import os

app = Flask(__name__)

# Initialize rate limiter to prevent brute force and DoS attacks
# Uses per-user rate limiting (user ID from JWT) with IP fallback
# Try Redis first, fall back to memory if Redis unavailable
try:
    import redis
    redis_client = redis.Redis(host='localhost', port=6379, socket_connect_timeout=2)
    redis_client.ping()
    storage_uri = "redis://localhost:6379"
    print("Flask-Limiter: Using Redis for rate limiting")
except (redis.ConnectionError, redis.TimeoutError, ImportError):
    storage_uri = "memory://"
    print("Flask-Limiter: Redis unavailable, using in-memory storage")

# Import per-user rate limiting key function
from app.rate_limit_key import get_user_id_or_ip

limiter = Limiter(
    app=app,
    key_func=get_user_id_or_ip,  # Per-user rate limiting
    default_limits=["200 per day", "50 per hour"],
    storage_uri=storage_uri
)

# Configure logging level from environment
import logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
app.logger.setLevel(getattr(logging, log_level, logging.INFO))

# Enable structured JSON logging with correlation IDs
# Set ENABLE_JSON_LOGGING=false in environment to disable for development
enable_json = os.environ.get("ENABLE_JSON_LOGGING", "true").lower() in ("true", "1", "yes")
if enable_json:
    from app.structured_logger import setup_structured_logging
    setup_structured_logging(app, enable_json=True)

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
# Default to False for self-signed certificates (common in HiveMatrix deployments)
# Can be overridden by setting VERIFY_SSL=True in .flaskenv if needed
verify_ssl_env = os.environ.get('VERIFY_SSL', 'False')
app.config['VERIFY_SSL'] = verify_ssl_env.lower() in ('true', '1', 'yes')
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

# Register RFC 7807 error handlers for consistent API error responses
from app.error_responses import (
    internal_server_error,
    not_found,
    bad_request,
    unauthorized,
    forbidden,
    service_unavailable
)

@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 Bad Request errors"""
    return bad_request(detail=str(e))

@app.errorhandler(401)
def handle_unauthorized(e):
    """Handle 401 Unauthorized errors"""
    return unauthorized(detail=str(e))

@app.errorhandler(403)
def handle_forbidden(e):
    """Handle 403 Forbidden errors"""
    return forbidden(detail=str(e))

@app.errorhandler(404)
def handle_not_found(e):
    """Handle 404 Not Found errors"""
    return not_found(detail=str(e))

@app.errorhandler(500)
def handle_internal_error(e):
    """Handle 500 Internal Server Error"""
    app.logger.error(f"Internal server error: {e}")
    return internal_server_error()

@app.errorhandler(503)
def handle_service_unavailable(e):
    """Handle 503 Service Unavailable errors"""
    return service_unavailable(detail=str(e))

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    """Catch-all handler for unexpected exceptions"""
    app.logger.exception(f"Unexpected error: {e}")
    return internal_server_error(detail="An unexpected error occurred")

# Configure OpenAPI/Swagger documentation
from flasgger import Swagger

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

swagger_template = {
    "info": {
        "title": f"{app.config.get('SERVICE_NAME', 'HiveMatrix')} API",
        "description": "API documentation for HiveMatrix Core service",
        "version": VERSION
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'"
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

Swagger(app, config=swagger_config, template=swagger_template)

from app import routes

# Log service startup
helm_logger.info(f"{app.config['SERVICE_NAME']} service started")
