# hook.py for the OIDC Plugin

from plugins.oidc.app.oidc_svc import OidcService
from plugins.oidc.app.oidc_api import OidcApi

name = 'OIDC'
description = 'A plugin that provides OIDC authentication for Caldera.'
address = None  # This plugin does not have a GUI component

async def enable(services):
    """
    This function is called by Caldera when the plugin is enabled.
    It initializes the OIDC service and sets up the necessary web routes.
    """
    # Create and register the OIDC service so other parts of the app can use it.
    oidc_svc = OidcService(services)
    services['oidc_svc'] = oidc_svc
    
    oidc_api = OidcApi(services)
    app = services.get('app_svc').application
    
    # This route will initiate the OIDC login flow.
    app.router.add_route('GET', '/login/oidc', oidc_api.oidc_login_redirect)
    
    # This route will handle the callback from the OIDC provider (e.g., Entra ID).
    app.router.add_route('GET', '/auth/oidc/callback', oidc_api.oidc_callback)
