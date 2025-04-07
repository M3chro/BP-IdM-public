from fastapi import FastAPI, Depends, HTTPException
import requests
from auth import verify_token, has_attribute, has_role, has_group
from config import KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_SERVER_URL
from schemas import TokenResponse, RefreshTokenResponse, ClientCredentialsResponse, ProtectedResponse


description = """
## Dokumentace k ukázce možné Keycloak integrace ve FastAPI

Tato dokumentace slouží k ukázce možné integrace Keycloaku do FastAPI.

V dokumentaci jsou popsány jednotlivé endpointy a způsoby, jak je možné je použít.

Pro získání přístupu k chráněným endpointům je třeba vpravo nahoře kliknout na tlačítko `Authorize` a vyplnit chybějící údaje (pro zjednodušení je předvyplněno).

Základní a doporučovaný grant pro autentizaci je **Authorization Code Grant**. Ten je zároveň doplňen o **PKCE** (Proof Key for Code Exchange), který je automaticky aktivován v nastavení Swagger UI.

"""

tags_metadata = [
    {
        "name": "auth_token_required",
        "description": "Operations post authentication. Basic CRUD operations. **Authorization and permission required.**",
    },
    {
        "name": "other_grant_types_examples",
        "description": "Operations with authentication. **No authorization required.**",
    }
]

app = FastAPI(
    title="Keycloak & FastAPI",
    description=description,
    openapi_tags=tags_metadata,
    swagger_ui_init_oauth = {
        "usePkceWithAuthorizationCodeGrant": True, # aktivace PKCE, Swagger UI automaticky generuje náhodný kód pro ověření
        "clientId": KEYCLOAK_CLIENT_ID,
        "clientSecret": KEYCLOAK_CLIENT_SECRET # předvyplnění pro snazší testování, nevhodné pro produkci!
    }
)

@app.get("/")
def welcome():
    """
    ## Přivítání uživatele
    
    **Přístup:** Otevřený pro všechny
    
    **Popis:** Vrací uvítací zprávu s odkazem na dokumentaci.
    """
    return {"message": "Vítejte! Přečtěte si dokumentaci na /docs."}


@app.post("/direct-access-grant", response_model=TokenResponse, tags=["other_grant_types_examples"])
def get_token_direct(username: str, password: str):
    """
    ## Přihlášení uživatele (Direct Access Grant)
    
    **Přístup:** Otevřený pro uživatele s platnými přihlašovacími údaji, v Keycloaku je třeba mít nastavené povolení pro tento grant (Direct access grants)
    
    **Popis:** Přihlášení pomocí uživatelského jména a hesla, **Password Grant** (nedoporučeno pro produkci, jedná se o legacy grant, který je nicméně velmi často uváděn stále). 
    """
    try:
        response = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "username": username,
                "password": password,
            }
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.json())
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Chyba komunikace se serverem: {str(e)}")

@app.post("/refresh-token", response_model=RefreshTokenResponse, tags=["other_grant_types_examples"])
def refresh_token(refresh_token: str):
    """
    ## Obnovení přístupového tokenu
    
    **Přístup:** Otevřený pro uživatele s platným refresh tokenem
    
    **Popis:** Umožňuje získání nového access tokenu pomocí refresh tokenu.
    """
    try:
        response = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "refresh_token",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "refresh_token": refresh_token,
            },
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.json())
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Chyba komunikace se serverem: {str(e)}")

@app.post("/client-credentials-grant", response_model=ClientCredentialsResponse, tags=["other_grant_types_examples"])
def get_token_client_credentials():
    """
    ## Přihlášení klienta (Client Credentials Grant)
    
    **Přístup:** Pouze pro registrované klienty, v Keycloaku je třeba mít nastavené povolení pro tento grant (Service accounts roles)
    
    **Popis:** Autentizace probíhá na úrovni klienta bez interakce s uživatelem, používá **Client Credentials Grant**.
    """
    try:
        response = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
            }
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.json())
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Chyba komunikace se serverem: {str(e)}")

@app.get("/protected", response_model=ProtectedResponse, tags=["auth_token_required"])
def protected_route(token: dict = Depends(verify_token)):
    """
    ## Chrání endpoint (ověření tokenu)
    
    **Přístup:** Pouze pro autentizované uživatele
    
    **Popis:** Ověří, zda je uživatel přihlášen, a vrátí jeho informace.
    """
    return {"message": "Tento endpoint je chráněný!", "user": token}
  
 
@app.get("/user", response_model=ProtectedResponse, tags=["auth_token_required"])
def user_route(user=Depends(has_role("user"))):
    """
    ## Endpoint pro běžného uživatele
    
    **Přístup:** Pouze pro uživatele s rolí `user`
    
    **Popis:** Endpoint ukazuje přístupové omezení pro běžné uživatele.
    """
    return {"message": "Přístup povolen pro běžného uživatele", "user": user}

@app.post("/admin", response_model=ProtectedResponse, tags=["auth_token_required"])
def admin_route(user=Depends(has_role("admin"))):
    """
    ## Endpoint pro admina
    
    **Přístup:** Pouze pro uživatele s rolí `admin`
    
    **Popis:** Pouze administrátoři mohou volat tento endpoint.
    """
    return {"message": "Přístup povolen pro admina", "user": user}

@app.put("/admin-group-only", response_model=ProtectedResponse, tags=["auth_token_required"])
def admin_only(user=Depends(has_group("admins"))):
    """
    ## Endpoint pro skupinu adminů
    
    **Přístup:** Pouze pro uživatele ve skupině `admins`
    
    **Popis:** Přístup je řízen na základě skupin, ne jen rolí.
    """
    return {"message": "Vítej v admin sekci!", "user": user}

@app.delete("/special-access", response_model=ProtectedResponse, tags=["auth_token_required"])
def special_access(user=Depends(has_attribute("department", "IT"))):
    """
    ## Speciální přístup (podle atributu uživatele)
    
    **Přístup:** Pouze pro uživatele s atributem `department=IT`
    
    **Popis:** Ukázkový endpoint pro omezení přístupu na základě specifických atributů uživatele.
    """
    return {"message": "Vítej v sekci se speciálním přístupem!", "user": user}