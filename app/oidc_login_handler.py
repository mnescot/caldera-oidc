# oidc_login_handler.py - The entry point for OIDC authentication.

import logging
from aiohttp import web

from app.service.interfaces.i_login_handler import LoginHandlerInterface

HANDLER_NAME = 'OIDC Login Handler'


def load_login_handler(services):
    """
    This is the required entry point for a Caldera login handler.
    """
    return OidcLoginHandler(services)


class OidcLoginHandler(LoginHandlerInterface):
    def __init__(self, services):
        """
        Initializes the OIDC Login Handler.
        """
        super().__init__(services, HANDLER_NAME)
        self.services = services
        self.log = logging.getLogger('oidc_login_handler')
        self.log.debug("OIDC Login Handler initialized.")

    async def handle_login(self, request, **kwargs):
        """
        Handles all login requests.
        - For GET requests (a user visiting the login page), it immediately
          redirects to the OIDC provider to start the login flow.
        - For POST requests (from the default login form, which shouldn't
          be reachable), it falls back to the default handler as a safety measure.
        """
        if request.method == 'GET':
            self.log.debug('GET request to login page. Initiating OIDC redirect.')
            # This redirects to the /login/oidc route we created in the API,
            # which then handles the redirect to the IdP.
            return web.HTTPFound('/login/oidc')
        else:
            # Fallback for any unexpected POST requests to the login page.
            auth_svc = self.services.get('auth_svc')
            self.log.debug('POST request received. Falling back to default login handler.')
            return await auth_svc.default_login_handler.handle_login(request, **kwargs)

