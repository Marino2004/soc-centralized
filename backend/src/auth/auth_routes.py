import base64
import hashlib
import logging
import os
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from src.auth import keycloak_auth
from src.auth.session import COOKIE_NAME, create_session_token, decode_session_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

FLOW_COOKIE_NAME = "soc_oidc_flow"
FLOW_COOKIE_MAX_AGE = 300
SESSION_MAX_AGE = 3600
# Mettre COOKIE_SECURE=true quand l'application est servie en HTTPS.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
# "lax" (et non "strict") : le retour depuis Keycloak est une navigation
# inter-sites, un cookie strict ne serait pas renvoye apres la redirection.
COOKIE_SAMESITE = "lax"


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@router.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)

    url = keycloak_auth.build_authorization_url(state, nonce, _pkce_challenge(code_verifier))
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(
        key=FLOW_COOKIE_NAME,
        value=f"{state}.{nonce}.{code_verifier}",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=FLOW_COOKIE_MAX_AGE,
        path="/api/auth",
    )
    return response


@router.get("/callback")
def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error or not code or not state:
        logger.info("Retour Keycloak en erreur: %s", error)
        return RedirectResponse("/?error=auth", status_code=302)

    flow = request.cookies.get(FLOW_COOKIE_NAME, "")
    try:
        expected_state, nonce, code_verifier = flow.split(".", 2)
    except ValueError:
        return RedirectResponse("/?error=auth", status_code=302)

    if not secrets.compare_digest(state, expected_state):
        logger.warning("State OIDC invalide")
        return RedirectResponse("/?error=auth", status_code=302)

    user = keycloak_auth.authenticate_code(code, code_verifier, nonce)
    if user is None:
        return RedirectResponse("/?error=forbidden", status_code=302)

    token = create_session_token(user.username, user.role)
    response = RedirectResponse("/action_plan", status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=SESSION_MAX_AGE,
    )
    response.delete_cookie(FLOW_COOKIE_NAME, path="/api/auth")
    logger.info("Login reussi pour %s (role=%s)", user.username, user.role)
    return response


@router.post("/logout")
def logout():
    # Le frontend redirige ensuite vers logout_url pour fermer la session Keycloak (SSO).
    response = JSONResponse({"detail": "Deconnecte", "logout_url": keycloak_auth.build_logout_url()})
    response.delete_cookie(
        key=COOKIE_NAME,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )
    logger.info("Deconnexion effectuee")
    return response


@router.get("/verify")
def verify(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token or decode_session_token(token) is None:
        raise HTTPException(401, "Session invalide")
    return {"ok": True}
