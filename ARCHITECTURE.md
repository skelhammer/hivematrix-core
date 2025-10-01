# HiveMatrix Architecture & AI Development Guide

**Version 3.1**

## 1. Core Philosophy & Goals

This document is the single source of truth for the HiveMatrix architecture. Its primary audience is the AI development assistant responsible for writing and maintaining the platform's code. Adherence to these principles is mandatory.

Our goals are, in order of priority:

1.  **AI Maintainability:** Each individual application (e.g., `Resolve`, `Codex`) must remain small, focused, and simple. We sacrifice some traditional development conveniences to achieve this.
2.  **Modularity:** The platform is a collection of independent, fully functional applications that can be composed together.
3.  **Simplicity & Explicitness:** We favor simple, explicit patterns over complex, "magical" ones. Assume code is correct and error out to expose flaws rather than building defensive checks.

## 2. The Monolithic Service Pattern

Each module in HiveMatrix (e.g., `Resolve`, `Architect`, `Codex`) is a **self-contained, monolithic application**. Each application is a single, deployable unit responsible for its own business logic, database, and UI rendering.

* **Server-Side Rendering:** Applications **must** render their user interfaces on the server side, returning complete HTML documents.
* **Data APIs:** Applications may *also* expose data-only APIs (e.g., `/api/tickets`) that return JSON.
* **Data Isolation:** Each service owns its own database. You are forbidden from accessing another service's database directly.

## 3. End-to-End Authentication Flow

The platform operates on a centralized login model orchestrated by `Core` and `Nexus`. No service handles user credentials directly.

1.  **Initial Request:** A user navigates to a protected resource, e.g., `http://nexus/codex/`.
2.  **Auth Check:** `Nexus` checks the user's session. If no valid session token exists, it stores the target URL (`/codex/`) and redirects the user to `Core` for login.
3.  **Keycloak Login:** `Core` immediately redirects the user to the Keycloak login page.
4.  **Callback to Core:** After successful login, Keycloak redirects the user back to `Core`'s `/auth` callback with an authorization code.
5.  **Token Minting:** `Core` exchanges the code for a Keycloak token, extracts the user info (including group membership for permission levels), and then **mints its own, internal HiveMatrix JWT**. This token is signed with `Core`'s private RSA key and includes:
    - User identity (sub, name, email, preferred_username)
    - Permission level (admin, technician, billing, or client) - derived from Keycloak groups
    - Group membership
    - Standard JWT claims (iss, iat, exp)
6.  **Callback to Nexus:** `Core` redirects the user back to `Nexus`'s `/auth-callback`, passing the new HiveMatrix JWT as a URL parameter.
7.  **Session Creation:** `Nexus` fetches `Core`'s public key from its `/.well-known/jwks.json` endpoint, verifies the JWT's signature and claims, and securely stores the token in the user's session.
8.  **Final Redirect:** `Nexus` redirects the user to their originally requested URL (`/codex/`).
9.  **Proxied & Authenticated Request:** Now logged in, `Nexus` proxies the request to the `Codex` service, adding the user's JWT in the `Authorization: Bearer <token>` header.
10. **Backend Verification:** The `Codex` service receives the request, fetches `Core`'s public key, verifies the JWT, and then processes the request, returning the protected HTML.

### Permission Levels

HiveMatrix supports four permission levels, determined by Keycloak group membership:

- **admin**: Members of the `admins` group - full system access
- **technician**: Members of the `technicians` group - technical operations
- **billing**: Members of the `billing` group - financial operations
- **client**: Default level for users not in any special group - limited access

Services can access the user's permission level via `g.user.get('permission_level')` and enforce authorization using the `@admin_required` decorator or custom permission checks.

## 4. Service-to-Service Communication

Services may need to call each other's APIs (e.g., Treasury calling Codex to get billing data). This is done using **service tokens** minted by Core.

### Service Token Flow

1. **Request Service Token:** The calling service (e.g., Treasury) makes a POST request to `Core`'s `/service-token` endpoint:
   ```json
   {
     "calling_service": "treasury",
     "target_service": "codex"
   }
   ```

2. **Core Mints Token:** Core creates a short-lived JWT (5 minutes) with:
   ```json
   {
     "iss": "hivematrix.core",
     "sub": "service:treasury",
     "calling_service": "treasury",
     "target_service": "codex",
     "type": "service",
     "iat": 1234567890,
     "exp": 1234568190
   }
   ```

3. **Make Authenticated Request:** The calling service uses this token in the Authorization header when calling the target service's API.

4. **Target Service Verification:** The target service verifies the token using Core's public key and checks the `type` field to determine if it's a service call.

### Service Client Helper

All services include a `service_client.py` helper that automates this flow:

```python
from app.service_client import call_service

# Make a service-to-service API call
response = call_service('codex', '/api/companies')
companies = response.json()
```

The `call_service` function:
- Automatically requests a service token from Core
- Adds the Authorization header
- Makes the HTTP request
- Returns the response

### Service Discovery

Services are registered in `services.json` for discovery:

```json
{
  "codex": {
    "url": "http://localhost:5010"
  },
  "treasury": {
    "url": "http://localhost:5011"
  }
}
```

### Authentication Decorator Behavior

The `@token_required` decorator in each service handles both user and service tokens:

```python
@token_required
def api_endpoint():
    if g.is_service_call:
        # Service-to-service call
        calling_service = g.service
        # Service calls bypass user-level permission checks
    else:
        # User call
        user = g.user
        # Apply user permission checks as needed
```

Service calls automatically bypass user-level permission requirements, as they represent trusted inter-service communication.

## 5. Frontend: The Smart Proxy Composition Model

The user interface is a composition of the independent applications, assembled by the `Nexus` proxy.

### The Golden Rule of Styling

**Applications are forbidden from containing their own styling.** All visual presentation (CSS) is handled exclusively by `Nexus` injecting a global stylesheet. Applications must use the BEM classes defined in this document.

### The `Nexus` Service

`Nexus` acts as the central gateway. Its responsibilities are:
* Enforcing authentication for all routes.
* Proxying requests to the appropriate backend service based on the URL path.
* Injecting the global `global.css` stylesheet into any HTML responses.
* Discovering backend services via the `services.json` file.

**File: `hivematrix-nexus/services.json`**
```json
{
  "template": {
    "url": "http://localhost:5001"
  },
  "codex": {
    "url": "http://localhost:5010"
  }
}
```

### URL Prefix Middleware

Each service must handle URL prefixes when behind the Nexus proxy. The `PrefixMiddleware` class adjusts the WSGI environment:

```python
# In app/__init__.py
from app.middleware import PrefixMiddleware
app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix=f'/{app.config["SERVICE_NAME"]}')
```

This allows services to generate correct URLs using Flask's `url_for()` when accessed through Nexus.

## 6. AI Instructions for Building a New Service

All new services (e.g., `Codex`, `Architect`) **must** be created by copying the `hivematrix-template` project. This ensures all necessary patterns are included.

### Step 1: Configuration

Every service requires an `app/__init__.py` that explicitly loads its configuration from a `.flaskenv` file. This is mandatory for security and proper function.

**File: `[new-service]/app/__init__.py` (Example)**

```python
from flask import Flask
import json
import os

app = Flask(__name__, instance_relative_config=True)

# --- Explicitly load all required configuration from environment variables ---
app.config['CORE_SERVICE_URL'] = os.environ.get('CORE_SERVICE_URL')
app.config['SERVICE_NAME'] = os.environ.get('SERVICE_NAME', 'myservice')

if not app.config['CORE_SERVICE_URL']:
    raise ValueError("CORE_SERVICE_URL must be set in the .flaskenv file.")

# Load database connection from config file
import configparser
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

config_path = os.path.join(app.instance_path, 'myservice.conf')
config = configparser.RawConfigParser()  # Use RawConfigParser for special chars
config.read(config_path)
app.config['MYSERVICE_CONFIG'] = config

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('database', 'connection_string',
    fallback=f"sqlite:///{os.path.join(app.instance_path, 'myservice.db')}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Load services configuration for service-to-service calls
try:
    with open('services.json') as f:
        services_config = json.load(f)
        app.config['SERVICES'] = services_config
except FileNotFoundError:
    print("WARNING: services.json not found. Service-to-service calls will not work.")
    app.config['SERVICES'] = {}

from extensions import db
db.init_app(app)

# Apply middleware to handle URL prefix when behind Nexus proxy
from app.middleware import PrefixMiddleware
app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix=f'/{app.config["SERVICE_NAME"]}')

from app import routes
```

**File: `[new-service]/.flaskenv` (Example)**

```
FLASK_APP=run.py
FLASK_ENV=development
CORE_SERVICE_URL='http://localhost:5000'
SERVICE_NAME='myservice'
```

### Step 2: Securing Routes

All routes that display user data or perform actions must be protected by the `@token_required` decorator. This decorator handles JWT verification for both user and service tokens.

**File: `[new-service]/app/auth.py` (Do not modify - copy from template)**

```python
from functools import wraps
from flask import request, g, current_app, abort
import jwt

jwks_client = None

def init_jwks_client():
    """Initializes the JWKS client from the URL in config."""
    global jwks_client
    core_url = current_app.config.get('CORE_SERVICE_URL')
    if core_url:
        jwks_client = jwt.PyJWKClient(f"{core_url}/.well-known/jwks.json")

def token_required(f):
    """
    A decorator to protect routes, ensuring a valid JWT is present.
    This now accepts both user tokens and service tokens.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if jwks_client is None:
            init_jwks_client()

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            abort(401, description="Authorization header is missing or invalid.")

        token = auth_header.split(' ')[1]

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            data = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer="hivematrix.core",
                options={"verify_exp": True}
            )

            # Determine if this is a user token or service token
            if data.get('type') == 'service':
                # Service-to-service call
                g.user = None
                g.service = data.get('calling_service')
                g.is_service_call = True
            else:
                # User call
                g.user = data
                g.service = None
                g.is_service_call = False

        except jwt.PyJWTError as e:
            abort(401, description=f"Invalid Token: {e}")

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin permission level."""
    @wraps(f)
    @token_required
    def decorated_function(*args, **kwargs):
        if g.is_service_call:
            # Services can access admin routes
            return f(*args, **kwargs)

        if not g.user or g.user.get('permission_level') != 'admin':
            abort(403, description="Admin access required.")

        return f(*args, **kwargs)
    return decorated_function
```

**File: `[new-service]/app/routes.py` (Example)**

```python
from flask import render_template, g, jsonify
from app import app
from .auth import token_required, admin_required

@app.route('/')
@token_required
def index():
    # Prevent service calls from accessing UI routes
    if g.is_service_call:
        return {'error': 'This endpoint is for users only'}, 403

    # The user's information is available in the 'g.user' object
    user = g.user
    return render_template('index.html', user=user)

@app.route('/api/data')
@token_required
def api_data():
    # This endpoint works for both users and services
    if g.is_service_call:
        # Service-to-service call from g.service
        return jsonify({'data': 'service response'})
    else:
        # User call - can check permissions
        if g.user.get('permission_level') != 'admin':
            return {'error': 'Admin only'}, 403
        return jsonify({'data': 'user response'})

@app.route('/admin/settings')
@admin_required
def admin_settings():
    # Only admins can access this
    return render_template('admin/settings.html', user=g.user)
```

### Step 3: Building the UI Template

HTML templates must be unstyled and use the BEM classes from the design system. User data from the JWT is passed into the template.

**File: `[new-service]/app/templates/index.html` (Example)**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My New Service</title>
</head>
<body>
    <div class="card">
        <div class="card__header">
            <h1 class="card__title">Hello, {{ user.name }}!</h1>
        </div>
        <div class="card__body">
            <p>Your username is: <strong>{{ user.preferred_username }}</strong></p>
            <p>Permission level: <strong>{{ user.permission_level }}</strong></p>
            <button class="btn btn--primary">
                <span class="btn__label">Primary Action</span>
            </button>
        </div>
    </div>
</body>
</html>
```

### Step 4: Database Initialization

Create an `init_db.py` script to interactively set up the database:

```python
import os
import sys
import configparser
from getpass import getpass
from sqlalchemy import create_engine
from dotenv import load_dotenv

load_dotenv('.flaskenv')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from extensions import db
from models import YourModel1, YourModel2  # Import your models

def get_db_credentials(config):
    """Prompts the user for PostgreSQL connection details."""
    print("\n--- PostgreSQL Database Configuration ---")

    # Load existing or use defaults
    db_details = {
        'host': config.get('database_credentials', 'db_host', fallback='localhost'),
        'port': config.get('database_credentials', 'db_port', fallback='5432'),
        'user': config.get('database_credentials', 'db_user', fallback='myservice_user'),
        'dbname': config.get('database_credentials', 'db_dbname', fallback='myservice_db')
    }

    host = input(f"Host [{db_details['host']}]: ") or db_details['host']
    port = input(f"Port [{db_details['port']}]: ") or db_details['port']
    dbname = input(f"Database Name [{db_details['dbname']}]: ") or db_details['dbname']
    user = input(f"User [{db_details['user']}]: ") or db_details['user']
    password = getpass("Password: ")

    return {'host': host, 'port': port, 'dbname': dbname, 'user': user, 'password': password}

def test_db_connection(creds):
    """Tests the database connection."""
    from urllib.parse import quote_plus

    escaped_password = quote_plus(creds['password'])
    conn_string = f"postgresql://{creds['user']}:{escaped_password}@{creds['host']}:{creds['port']}/{creds['dbname']}"

    try:
        engine = create_engine(conn_string)
        with engine.connect() as connection:
            print("\n✓ Database connection successful!")
            return conn_string, True
    except Exception as e:
        print(f"\n✗ Connection failed: {e}", file=sys.stderr)
        return None, False

def init_db():
    """Interactively configures and initializes the database."""
    instance_path = app.instance_path
    config_path = os.path.join(instance_path, 'myservice.conf')

    config = configparser.RawConfigParser()

    if os.path.exists(config_path):
        config.read(config_path)
        print(f"\n✓ Existing configuration found: {config_path}")
    else:
        print(f"\n→ Creating new config: {config_path}")
        os.makedirs(instance_path, exist_ok=True)

    # Database configuration
    while True:
        creds = get_db_credentials(config)
        conn_string, success = test_db_connection(creds)
        if success:
            if not config.has_section('database'):
                config.add_section('database')
            config.set('database', 'connection_string', conn_string)

            if not config.has_section('database_credentials'):
                config.add_section('database_credentials')
            for key, val in creds.items():
                if key != 'password':
                    config.set('database_credentials', f'db_{key}', val)
            break
        else:
            if input("\nRetry? (y/n): ").lower() != 'y':
                sys.exit("Database configuration aborted.")

    # Save configuration
    with open(config_path, 'w') as configfile:
        config.write(configfile)
    print(f"\n✓ Configuration saved to: {config_path}")

    # Initialize database schema
    with app.app_context():
        print("\nInitializing database schema...")
        db.create_all()
        print("✓ Database schema initialized successfully!")

if __name__ == '__main__':
    init_db()
```

## 7. Running the Development Environment

To run the full platform, you must start each service in its own terminal on its designated port.

1.  **Keycloak:** `./kc.sh start-dev` (Runs on port `8080`)
2.  **Core:** `flask run --port=5000`
3.  **Nexus:** `flask run --port=8000`
4.  **Template:** `flask run --port=5001`
5.  **Codex:** `flask run --port=5010`
6.  ...and so on for other services.

Access the platform through the Nexus URL: `http://localhost:8000`.

## 8. Design System & BEM Classes

_(This section will be expanded with more components as they are built.)_

### Component: Card (`.card`)

-   **Block:** `.card` - The main container.
-   **Elements:** `.card__header`, `.card__title`, `.card__body`

### Component: Button (`.btn`)

-   **Block:** `.btn`
-   **Elements:** `.btn__icon`, `.btn__label`
-   **Modifiers:** `.btn--primary`, `.btn--danger`

### Component: Table

-   **Block:** `table` - Standard HTML table element
-   **Elements:** `thead`, `tbody`, `th`, `td`
-   Styling is provided globally by Nexus

### Component: Form Elements

-   **Input:** Standard `input`, `select`, `textarea` elements
-   **Label:** Standard `label` element
-   Styling is provided globally by Nexus

## 9. Database Best Practices

### Configuration Storage

- Use `configparser.RawConfigParser()` instead of `ConfigParser()` to handle special characters in passwords
- Store database credentials in `instance/[service].conf`
- Never commit config files to version control (they're in `.gitignore`)

### Models

- Each service owns its own database tables
- Use SQLAlchemy for ORM
- Define models in `models.py`
- Use appropriate data types:
  - `db.String(50)` for short strings (IDs, codes)
  - `db.String(150)` for names
  - `db.String(255)` for URLs, domains
  - `db.Text` for long text fields
  - `BigInteger` for large numeric IDs (like Freshservice IDs)

### Relationships

- Use association tables for many-to-many relationships
- Use `db.relationship()` with `back_populates` for bidirectional relationships
- Add `cascade="all, delete-orphan"` for proper cleanup

## 10. External System Integration

### Sync Scripts

Services that integrate with external systems (like Codex with Freshservice and Datto) should:

- Have standalone Python scripts (e.g., `pull_freshservice.py`, `pull_datto.py`)
- Import the Flask app and models directly
- Use the app context: `with app.app_context():`
- Be runnable via cron for automated syncing
- Include proper error handling and logging

### API Credentials

- Store API credentials in the service's config file
- Never hardcode credentials
- Provide interactive setup via `init_db.py`

## 11. Common Patterns

### Service Directory Structure

```
hivematrix-myservice/
├── app/
│   ├── __init__.py           # Flask app initialization
│   ├── auth.py               # @token_required decorator
│   ├── routes.py             # Main web routes
│   ├── service_client.py     # Service-to-service helper
│   ├── middleware.py         # URL prefix middleware
│   └── templates/            # HTML templates (BEM styled)
│       └── admin/            # Admin-only templates
├── routes/                   # Blueprint routes (optional)
│   ├── __init__.py
│   ├── entities.py
│   └── admin.py
├── instance/
│   └── myservice.conf        # Configuration (not in git)
├── extensions.py             # Flask extensions (db)
├── models.py                 # SQLAlchemy models
├── init_db.py                # Database initialization script
├── run.py                    # Application entry point
├── services.json             # Service discovery config
├── requirements.txt          # Python dependencies
├── .flaskenv                 # Environment variables (not in git)
├── .gitignore
└── README.md
```

### Required Files

Every service must have:
- `.flaskenv` - Environment configuration
- `requirements.txt` - Python dependencies
- `run.py` - Entry point
- `app/__init__.py` - Flask app setup
- `app/auth.py` - Authentication decorators (copy from template)
- `app/service_client.py` - Service-to-service helper (copy from template)
- `app/middleware.py` - URL prefix middleware (copy from template)
- `extensions.py` - Flask extensions
- `models.py` - Database models
- `init_db.py` - Interactive database setup
- `services.json` - Service discovery

## 12. Version History

- **3.1** - Added service-to-service communication, permission levels, database best practices, external integrations
- **3.0** - Initial version with core architecture patterns
