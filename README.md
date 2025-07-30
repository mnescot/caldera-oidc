# Caldera OIDC Authentication Plugin
This plugin provides OpenID Connect (OIDC) authentication for MITRE Caldera, allowing integration with identity providers like Microsoft Entra ID, Okta, and others.

Features
Redirects unauthenticated users to your OIDC provider for login.

Handles the OIDC callback and token exchange.

Automatically creates new Caldera users upon their first successful login.

Falls back to the default login handler for any non-OIDC login attempts.

Installation
Clone this repository into the caldera/plugins directory:

git clone <your-repo-url> plugins/oidc

Install the plugin's dependencies:

pip install -r plugins/oidc/requirements.txt

Configuration
Create a settings.json file in the plugins/oidc/conf directory. See settings.json.example for the required structure.

Update your conf/local.yml file to enable the plugin and set it as the login handler:

plugins:
  - oidc

auth:
  login_handler: plugins.oidc.app.oidc_login_handler
