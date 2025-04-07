import json
import os
from dotenv import find_dotenv, load_dotenv
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, session, url_for, request, jsonify, g
from flask_cors import cross_origin
from urllib.request import urlopen
from functools import wraps
from jose import jwt
from flasgger import Swagger

# Kód převzat a upraven do vlastní podoby z: https://auth0.com/docs/quickstart/backend/python
# Obohacen o Swagger UI na endpointu /apidocs

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Konfigurace Auth0
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

# Swagger nastavení (s Bearer autentizací)
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Auth0 API",
        "description": """API chráněné pomocí Auth0
                        Bearer token je nutný pro přístup k privátním endpointům.
        """,
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Zadejte Bearer token ve formátu: Bearer TOKEN"
        }
    },
    "security": [{"Bearer": []}]
}
swagger = Swagger(app, template=swagger_template)

# Error handler pro autentizaci
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Získání access tokenu z hlavičky
def get_token_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description": "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description": "Authorization header must start with Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description": "Authorization header must be Bearer token"}, 401)

    return parts[1]

# Middleware pro validaci JWT tokenu
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        try:
            jsonurl = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
            jwks = json.loads(jsonurl.read())
            unverified_header = jwt.get_unverified_header(token)
            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
            if not rsa_key:
                raise AuthError({"code": "invalid_header",
                                "description": "Unable to find appropriate key"}, 401)
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/"
            )
            g.current_user = payload
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "Token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description": "Incorrect claims, check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description": "Unable to parse authentication token."}, 401)

        return f(*args, **kwargs)
    return decorated

# Ověření scope oprávnění
def requires_scope(required_scope):
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if "scope" in unverified_claims:
        token_scopes = unverified_claims["scope"].split()
        return required_scope in token_scopes
    return False

def requires_permission(permission):
    """Checks if the Access Token has the required permission"""
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("permissions"):
        token_permissions = unverified_claims["permissions"]
        if permission in token_permissions:
            return True
    return False

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email"
    },
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration'
)


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True), audience=API_AUDIENCE
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + AUTH0_DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": AUTH0_CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )
    
# Veřejný endpoint
@app.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    """Public API endpoint
    ---
    responses:
      200:
        description: No authentication required
    """
    return jsonify(message="Hello from a public endpoint! No authentication required.")

# Privátní endpoint
@app.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def private():
    """Private API endpoint
    ---
    security:
      - Bearer: []
    responses:
      200:
        description: Requires valid access token
      401:
        description: Unauthorized
    """
    return jsonify(message="Hello from a private endpoint! Authentication required.")

# Endpoint se scopem
@app.route("/api/private-scoped")
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def private_scoped():
    """Private Scoped API endpoint
    ---
    security:
      - Bearer: []
    responses:
      200:
        description: Requires valid token with correct scope
      401:
        description: Unauthorized
      403:
        description: Insufficient permissions
    """
    if requires_permission("read:test"):
        return jsonify(message="Hello from a private scoped endpoint!")
    raise AuthError({"code": "Unauthorized",
                     "description": "You don't have access to this resource"}, 403)

@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)