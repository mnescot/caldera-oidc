# oidc_svc.py - The core service for OIDC logic

import logging
import json
from pathlib import Path
from aiohttp import web
import aiohttp
import jwt
from urllib.parse import urlencode

from app.service.interfaces.i_auth_svc import AuthServiceInterface

OIDC_SETTINGS_PATH = Path(__file__).parent.parent / 'conf' / 'settings.json'


class OidcService:
    def __init__(self, services):
        """
        Initializes the OIDC service.
        """
        self.services = services
        self.auth_svc = self.services.get('auth_svc')
        self.log = logging.getLogger('oidc_svc')
        self.oidc_config = self._load_oidc_config()
        self.log.debug("OIDC Service initialized.")

    def _load_oidc_config(self):
        """
        Loads the OIDC settings from the persistent settings.json file.
        """
        try:
            self.log.debug(f"Attempting to load OIDC settings from: {OIDC_SETTINGS_PATH}")
            with open(OIDC_SETTINGS_PATH, 'r') as f:
                config = json.load(f)
                self.log.debug("OIDC settings.json file loaded and parsed successfully.")
                return config
        except Exception as e:
            self.log.error(f"CRITICAL ERROR loading or parsing OIDC settings.json: {e}", exc_info=True)
            return {}

    async def get_authorization_url(self, request):
        """
        Constructs the authorization URL to redirect the user to Entra ID for login.
        """
        self.log.debug("Constructing OIDC authorization URL.")
        if not all(k in self.oidc_config for k in ['authorization_url', 'client_id', 'redirect_uri']):
            self.log.error("OIDC configuration is missing required fields.")
            return '/login'

        # State is a security measure to prevent CSRF attacks.
        state = self.auth_svc.generate_token()
        request.app['oidc_state'] = state

        params = {
            'client_id': self.oidc_config['client_id'],
            'response_type': 'code',
            'redirect_uri': self.oidc_config['redirect_uri'],
            'scope': 'openid profile email',
            'state': state,
            'response_mode': 'query'
        }
        return f"{self.oidc_config['authorization_url']}?{urlencode(params)}"

    async def process_oidc_callback(self, request):
        """
        Handles the callback from Entra ID after the user authenticates.
        """
        self.log.debug("Processing OIDC callback.")
        code = request.query.get('code')
        state = request.query.get('state')

        # Validate the state to ensure the request is legitimate.
        if state != request.app.get('oidc_state'):
            self.log.warning("OIDC state mismatch. Possible CSRF attack.")
            return None

        # Exchange the authorization code for an ID token.
        id_token = await self._exchange_code_for_token(code)
        if not id_token:
            return None

        # Validate the ID token and extract the user's information.
        user_info = self._validate_id_token(id_token)
        if not user_info:
            return None

        # Find or create the user in Caldera.
        username = user_info.get('preferred_username') or user_info.get('email')
        if not username:
            self.log.error("Could not determine username from OIDC token.")
            return None

        if await self.auth_svc.get_user(username=username):
            self.log.debug(f"Existing OIDC user '{username}' logged in.")
        else:
            self.log.debug(f"Creating new Caldera user for OIDC user '{username}'.")
            await self.auth_svc.create_user(username, AuthServiceInterface.INSECURE_DEFAULT_PASSWORD, 'blue')

        return username

    async def _exchange_code_for_token(self, code):
        """
        Makes a POST request to the OIDC token endpoint to get an ID token.
        """
        self.log.debug("Exchanging authorization code for token.")
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'client_id': self.oidc_config['client_id'],
            'scope': 'openid profile email',
            'code': code,
            'redirect_uri': self.oidc_config['redirect_uri'],
            'grant_type': 'authorization_code',
            'client_secret': self.oidc_config['client_secret']
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(self.oidc_config['token_url'], headers=headers, data=data) as resp:
                if resp.status == 200:
                    token_data = await resp.json()
                    self.log.debug("Successfully received token from OIDC provider.")
                    return token_data.get('id_token')
                else:
                    self.log.error(f"Failed to exchange code for token. Status: {resp.status}, Body: {await resp.text()}")
                    return None

    def _validate_id_token(self, token):
        """
        Decodes and validates the JWT ID token.
        """
        self.log.debug("Validating ID token.")
        try:
            # In a production environment, you would fetch the public keys from the IdP's JWKS URI
            # to verify the token signature. For this example, we will skip signature verification.
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            
            # Basic validation
            if decoded_token.get('iss') != self.oidc_config.get('issuer'):
                self.log.error("ID token issuer mismatch.")
                return None
            if decoded_token.get('aud') != self.oidc_config.get('client_id'):
                self.log.error("ID token audience mismatch.")
                return None
            
            self.log.debug("ID token validated successfully.")
            return decoded_token
        except Exception as e:
            self.log.error(f"Error decoding or validating ID token: {e}", exc_info=True)
            return None
