# HiveMatrix Architecture & AI Development Guide

**Version 3.0**

## 1. Core Philosophy & Goals

This document is the single source of truth for the HiveMatrix architecture. Its primary audience is the AI development assistant responsible for writing and maintaining the platform's code. Adherence to these principles is mandatory.

Our goals are, in order of priority:

1.  **AI Maintainability:** Each individual application (e.g., `Resolve`) must remain small, focused, and simple. We sacrifice some traditional development conveniences to achieve this.
2.  **Modularity:** The platform is a collection of independent, fully functional applications that can be composed together.
3.  **Simplicity & Explicitness:** We favor simple, explicit patterns over complex, "magical" ones. Assume code is correct and error out to expose flaws rather than building defensive checks.

## 2. The Monolithic Service Pattern

Each module in HiveMatrix (e.g., `Resolve`, `Architect`) is a **self-contained, monolithic application**. Each application is a single, deployable unit responsible for its own business logic, database, and UI rendering.

* **Server-Side Rendering:** Applications **must** render their user interfaces on the server side, returning complete HTML documents.
* **Data APIs:** Applications may *also* expose data-only APIs (e.g., `/api/tickets`) that return JSON.
* **Data Isolation:** Each service owns its own database. You are forbidden from accessing another service's database directly.

## 3. End-to-End Authentication Flow

The platform operates on a centralized login model orchestrated by `Core` and `Nexus`. No service handles user credentials directly.



1.  **Initial Request:** A user navigates to a protected resource, e.g., `http://nexus/template/`.
2.  **Auth Check:** `Nexus` checks the user's session. If no valid session token exists, it stores the target URL (`/template/`) and redirects the user to `Core` for login.
3.  **Keycloak Login:** `Core` immediately redirects the user to the Keycloak login page.
4.  **Callback to Core:** After successful login, Keycloak redirects the user back to `Core`'s `/auth` callback with an authorization code.
5.  **Token Minting:** `Core` exchanges the code for a Keycloak token, extracts the user info, and then **mints its own, internal HiveMatrix JWT**. This token is signed with `Core`'s private RSA key.
6.  **Callback to Nexus:** `Core` redirects the user back to `Nexus`'s `/auth-callback`, passing the new HiveMatrix JWT as a URL parameter.
7.  **Session Creation:** `Nexus` fetches `Core`'s public key from its `/.well-known/jwks.json` endpoint, verifies the JWT's signature and claims, and securely stores the token in the user's session.
8.  **Final Redirect:** `Nexus` redirects the user to their originally requested URL (`/template/`).
9.  **Proxied & Authenticated Request:** Now logged in, `Nexus` proxies the request to the `Template` service, adding the user's JWT in the `Authorization: Bearer <token>` header.
10. **Backend Verification:** The `Template` service receives the request, fetches `Core`'s public key, verifies the JWT, and then processes the request, returning the protected HTML.

## 4. Frontend: The Smart Proxy Composition Model

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
    "url": "http://localhost:5002"
  }
}

```

## 5. AI Instructions for Building a New Service

All new services (e.g., `Codex`, `Architect`) **must** be created by copying the `hivematrix-template` project. This ensures all necessary patterns are included.

### Step 1: Configuration

Every service requires an `app/__init__.py` that explicitly loads its configuration from a `.flaskenv` file. This is mandatory for security and proper function.

**File: `[new-service]/app/__init__.py` (Example)**

Python

```
from flask import Flask
import os

app = Flask(__name__)

# Explicitly load all required configuration from environment variables
app.config['CORE_SERVICE_URL'] = os.environ.get('CORE_SERVICE_URL')

# Add any other service-specific config variables here
# app.config['DATABASE_URI'] = os.environ.get('DATABASE_URI')

if not app.config['CORE_SERVICE_URL']:
    raise ValueError("CORE_SERVICE_URL must be set in the .flaskenv file.")

from app import routes

```

**File: `[new-service]/.flaskenv` (Example)**

Plaintext

```
FLASK_APP=run.py
FLASK_ENV=development
CORE_SERVICE_URL='http://localhost:5000'
# Add other service-specific env vars here
# DATABASE_URI='sqlite:///app.db'

```

### Step 2: Securing Routes

All routes that display user data or perform actions must be protected by the `@token_required` decorator. This decorator handles JWT verification.

**File: `[new-service]/app/auth.py` (Do not modify)**

Python

```
from functools import wraps
from flask import request, g, current_app, abort
import jwt

# This file should be copied verbatim from hivematrix-template

jwks_client = None

def init_jwks_client():
    # ... (implementation from template)

def token_required(f):
    # ... (implementation from template)

```

**File: `[new-service]/app/routes.py` (Example)**

Python

```
from flask import render_template, g
from app import app
from .auth import token_required

@app.route('/')
@token_required # This decorator protects the route
def index():
    # The user's information is available in the 'g.user' object
    user = g.user
    return render_template('index.html', user=user)

```

### Step 3: Building the UI Template

HTML templates must be unstyled and use the BEM classes from the design system. User data from the JWT is passed into the template.

**File: `[new-service]/app/templates/index.html` (Example)**

HTML

```
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
            <button class="btn btn--primary">
                <span class="btn__label">Primary Action</span>
            </button>
        </div>
    </div>
</body>
</html>

```

## 6. Running the Development Environment

To run the full platform, you must start each service in its own terminal on its designated port.

1.  **Keycloak:** `./kc.sh start-dev` (Runs on port `8080`)

2.  **Core:** `flask run --port=5000`

3.  **Nexus:** `flask run --port=8000`

4.  **Template:** `flask run --port=5001`

5.  **Codex (New Service):** `flask run --port=5002`

6.  ...and so on for other services.


Access the platform through the Nexus URL: `http://localhost:8000`.

## 7. Design System & BEM Classes

_(This section will be expanded with more components as they are built.)_

### Component: Card (`.card`)

-   **Block:** `.card` - The main container.

-   **Elements:** `.card__header`, `.card__title`, `.card__body`


### Component: Button (`.btn`)

-   **Block:** `.btn`

-   **Elements:** `.btn__icon`, `.btn__label`

-   **Modifiers:** `.btn--primary`, `.btn--danger`
