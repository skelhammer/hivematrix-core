
# hivematrix-core

Core of Hivematrix. This service is the central Identity and Access Management (IAM) hub.

It acts as an **abstraction layer** in front of a **Keycloak** backend. All other HiveMatrix services (like Nexus, Resolve, etc.) will communicate **only with Core** for authentication and user information. This decouples the rest of the platform from the underlying IAM provider.

## Architecture Overview

The authentication flow is as follows:

1.  A user attempts to access a protected resource in `Nexus`.

2.  `Nexus` redirects the user to `Core`'s `/login` endpoint.

3.  `Core` initiates an OpenID Connect (OIDC) login flow, redirecting the user to the Keycloak login page.

4.  The user authenticates with Keycloak.

5.  Keycloak redirects the user back to a callback endpoint on `Core`.

6.  `Core` exchanges the authorization code from Keycloak for an access token and stores the user's session information.

7.  `Core` redirects the user back to the original page they were trying to access in `Nexus`.


## Part 1: Keycloak Backend Setup

Follow these steps to install and configure the Keycloak instance that Core will communicate with.

### 1.1 Prerequisites

```
sudo apt update
sudo apt install -y openjdk-17-jre-headless wget unzip

```

### 1.2 Native Installation & Running

```
# Download and unpack
wget https://github.com/keycloak/keycloak/releases/download/26.3.5/keycloak-26.3.5.zip
unzip keycloak-26.3.5.zip

# Set initial admin credentials (first run only)
export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=admin

# Start the server
cd keycloak-26.3.5/bin/
./kc.sh start-dev

```

Access the Admin Console at http://localhost:8080 and log in with `admin` / `admin`.

### 1.3 Keycloak Configuration for Core

#### A. Create the `hivematrix` Realm

1.  Manage realms -> Create Realm

2.  **Realm name:**  `hivematrix`

3.  Click `Create`.


#### B. Create and Configure the `core-client`

This client represents the `Core` Flask application itself.

1.  In the `hivematrix` realm, go to `Clients` and click `Create client`.

2.  **Client ID:**  `core-client`

3.  **Name:**  `HiveMatrix Core Service`

4.  Click `Next`.

5.  Ensure `Standard flow` is checked.

6.  Toggle "Client authentication" to ON and hit next.

7.  In the **Valid redirect URIs** field, enter the callback URL for our Flask app:

    -   `http://127.0.0.1:5000/auth`

8.  Click `Save`.


#### C. Get the Client Secret

1.  After saving, a `Credentials` tab will appear.

2.  Click it and copy the `Client secret`. You will need this for the Flask app's configuration.


#### D. Create a Test User

1.  Go to `Users` -> `Create new user`.

2.  Enter a username (e.g., `dhamner`).

3.  Go to the `Credentials` tab for the new user, set a password, and turn the `Temporary` switch **OFF**.


Keycloak is now ready for the `Core` service.

## Part 2: HiveMatrix Core Service Setup

Follow these steps to run the Python Flask application that serves as the proxy to Keycloak.

### 2.1 Install Dependencies

Create a virtual environment and install the required packages.

```
python -m venv pyenv
source pyenv/bin/activate
pip install -r requirements.txt

```

### 2.2 Configure Environment Variables

Create a `.flaskenv` file in the root directory with the following content. Replace `<YOUR_CLIENT_SECRET>` with the one you copied from Keycloak.

```
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY='a-very-secret-key-for-flask-sessions'

# Keycloak OIDC Settings
KEYCLOAK_SERVER_URL='http://localhost:8080/realms/hivematrix'
KEYCLOAK_CLIENT_ID='core-client'
KEYCLOAK_CLIENT_SECRET='<YOUR_CLIENT_SECRET>'

```

### 2.3 Run the Core Service

```
flask run

```

The Core service will now be running on `http://localhost:5000`. You can test the login flow by navigating to this URL.
