import os
import logging
from dataclasses import dataclass
from urllib.parse import urlencode

import jwt
import requests
from jwt import PyJWKClient, PyJWTError

logger = logging.getLogger(__name__)

# URL publique de Keycloak (celle vue par le navigateur ET l'"iss" des tokens).
KEYCLOAK_URL = os.environ["KEYCLOAK_URL"].strip().rstrip("/")
# URL joignable depuis le conteneur (appels serveur -> serveur). Optionnelle.
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", KEYCLOAK_URL).strip().rstrip("/")
KEYCLOAK_REALM = os.environ["KEYCLOAK_REALM"].strip()
KEYCLOAK_CLIENT_ID = os.environ["KEYCLOAK_CLIENT_ID"].strip()
KEYCLOAK_CLIENT_SECRET = os.environ["KEYCLOAK_CLIENT_SECRET"].strip()
# URL publique de l'application (ex: http://soc.example:8088), sans slash final.
APP_BASE_URL = os.environ["APP_BASE_URL"].strip().rstrip("/")

# Noms des rôles Keycloak (realm ou client) -> rôles applicatifs.
# L'ordre compte : le premier rôle trouvé l'emporte (admin_cyber avant technicien).
ROLE_MAP = [
    (os.environ.get("KEYCLOAK_ROLE_ADMIN", "admin_cyber"), "admin_cyber"),
    (os.environ.get("KEYCLOAK_ROLE_TECH", "technicien"), "technicien"),
]

REALM_PATH = f"/realms/{KEYCLOAK_REALM}"
ISSUER = f"{KEYCLOAK_URL}{REALM_PATH}"
AUTH_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
LOGOUT_ENDPOINT = f"{ISSUER}/protocol/openid-connect/logout"
TOKEN_ENDPOINT = f"{KEYCLOAK_INTERNAL_URL}{REALM_PATH}/protocol/openid-connect/token"
JWKS_ENDPOINT = f"{KEYCLOAK_INTERNAL_URL}{REALM_PATH}/protocol/openid-connect/certs"

REDIRECT_URI = f"{APP_BASE_URL}/api/auth/callback"
POST_LOGOUT_REDIRECT_URI = f"{APP_BASE_URL}/"

_jwks_client = PyJWKClient(JWKS_ENDPOINT, cache_keys=True)


@dataclass
class AuthenticatedUser:
    username: str
    role: str


def build_authorization_url(state: str, nonce: str, code_challenge: str) -> str:
    params = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def build_logout_url() -> str:
    params = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI,
    }
    return f"{LOGOUT_ENDPOINT}?{urlencode(params)}"


def _decode(token: str, **options) -> dict:
    signing_key = _jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=ISSUER,
        **options,
    )


def _extract_role(access_claims: dict) -> str | None:
    realm_roles = access_claims.get("realm_access", {}).get("roles", [])
    client_roles = (
        access_claims.get("resource_access", {}).get(KEYCLOAK_CLIENT_ID, {}).get("roles", [])
    )
    granted = set(realm_roles) | set(client_roles)
    for keycloak_role, app_role in ROLE_MAP:
        if keycloak_role in granted:
            return app_role
    return None


def authenticate_code(code: str, code_verifier: str, expected_nonce: str) -> AuthenticatedUser | None:
    """Echange le code d'autorisation, valide les tokens et resout le role SOC."""
    try:
        resp = requests.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "code_verifier": code_verifier,
            },
            timeout=10,
        )
    except requests.RequestException:
        logger.exception("Keycloak injoignable lors de l'echange du code")
        return None

    if resp.status_code != 200:
        logger.warning("Echange du code refuse par Keycloak (HTTP %s)", resp.status_code)
        return None

    tokens = resp.json()

    try:
        id_claims = _decode(tokens["id_token"], audience=KEYCLOAK_CLIENT_ID)
        # L'audience de l'access token vaut "account" par defaut : on verifie
        # la signature, l'emetteur et l'expiration, pas l'audience.
        access_claims = _decode(tokens["access_token"], options={"verify_aud": False})
    except (PyJWTError, KeyError):
        logger.exception("Validation des tokens Keycloak echouee")
        return None

    if id_claims.get("nonce") != expected_nonce:
        logger.warning("Nonce OIDC invalide")
        return None

    username = id_claims.get("preferred_username") or id_claims.get("sub")
    role = _extract_role(access_claims)
    if role is None:
        logger.warning("Utilisateur %s authentifie mais aucun role SOC connu", username)
        return None

    return AuthenticatedUser(username=username, role=role)
