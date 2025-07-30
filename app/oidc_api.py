import logging
from aiohttp import web

class OidcApi:
    def __init__(self, services):
        """
        Initializes the OIDC API handler.
        """
        self.services = services
        self.oidc_svc = self.services.get('oidc_svc')
        self.auth_svc = self.services.get('auth_svc')
        self.log = logging.getLogger('oidc_api')
        self.log.debug("OIDC API handler initialized.")

    async def oidc_login_redirect(self, request):
        """
        Initiates the OIDC login flow by redirecting the user to the IdP.
        """
        self.log.debug("Redirecting user to OIDC provider for login.")
        auth_url = await self.oidc_svc.get_authorization_url(request)
        return web.HTTPFound(auth_url)

    async def oidc_callback(self, request):
        """
        This is the callback endpoint that Entra ID will redirect to after a
        successful login.
        """
        self.log.debug("Received request at /auth/oidc/callback endpoint.")
        try:
            username = await self.oidc_svc.process_oidc_callback(request)
            if username:
                self.log.info(f"OIDC user '{username}' successfully authenticated.")
                # Establish a session for the user.
                await self.auth_svc.login_user(request, username=username)
                return web.HTTPFound('/')
            else:
                self.log.warning("OIDC authentication failed.")
                return web.HTTPFound('/login')
        except Exception as e:
            self.log.error(f"Error in OIDC callback: {e}", exc_info=True)
            return web.HTTPFound('/login')
