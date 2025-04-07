from fastapi import Depends, HTTPException, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, ExpiredTokenError, InvalidClaimError
import requests
from config import KEYCLOAK_REALM, KEYCLOAK_EXTERNAL_URL, KEYCLOAK_SERVER_URL
from cachetools import TTLCache, cached

# OAuth2 schéma pro FastAPI (Swagger používá `KEYCLOAK_EXTERNAL_URL`)
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_EXTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_EXTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
)

# Vytvoření cache pro JWKS s platností 10 minut (600 sekund)
jwks_cache = TTLCache(maxsize=1, ttl=600)

def get_openid_config():
    """Dynamicky načte OpenID konfiguraci z Keycloaku."""
    openid_config_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
    try:
        response = requests.get(openid_config_url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Nelze načíst OpenID konfiguraci: {e}")

@cached(jwks_cache)
def get_jwks():
    """Načte JWKS klíče a cacheuje je na 10 minut."""
    openid_config = get_openid_config()  # OpenID konfigurace se získává dynamicky
    jwks_uri = openid_config["jwks_uri"]
    
    try:
        response = requests.get(jwks_uri)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Chyba při načítání JWKS: {e}")

# Funkce pro ověření a dekódování tokenu
def verify_token(token: str = Security(oauth2_scheme)):
    jwks = get_jwks()  # Využití cache
    try:
        claims = jwt.decode(token, key=jwks, claims_options={"verify_exp": True})
        return claims
    except BadSignatureError:
        raise HTTPException(status_code=401, detail="Neplatný podpis tokenu")
    except ExpiredTokenError:
        raise HTTPException(status_code=401, detail="Token vypršel")
    except InvalidClaimError:
        raise HTTPException(status_code=401, detail="Neplatný claim v tokenu")
    except Exception:
        raise HTTPException(status_code=401, detail="Neplatný nebo neověřitelný token")

def has_attribute(required_attribute: str, required_value: str):
    """ Dekorátor pro kontrolu atributů """
    def attribute_checker(token=Depends(verify_token)):
        attribute_value = token.get(required_attribute)
        if attribute_value != required_value:
            raise HTTPException(status_code=403, detail=f"Požadovaný atribut '{required_attribute}' musí mít hodnotu '{required_value}'")
        return token
    return attribute_checker

def has_role(required_role: str):
    """ Dekorátor pro kontrolu klientských rolí """
    def role_checker(token=Depends(verify_token)):
        client_roles = token.get("resource_access", {}).get("fastapi-app", {}).get("roles", [])
        if required_role not in client_roles:
            raise HTTPException(status_code=403, detail=f"Uživatel nemá požadovanou roli: {required_role}")
        return token
    return role_checker

def has_group(required_group: str):
    """ Dekorátor pro kontrolu skupin """
    def group_checker(token=Depends(verify_token)):
        groups = token.get("groups", [])
        if required_group not in groups:
            raise HTTPException(status_code=403, detail=f"Uživatel není členem skupiny: {required_group}")
        return token
    return group_checker
