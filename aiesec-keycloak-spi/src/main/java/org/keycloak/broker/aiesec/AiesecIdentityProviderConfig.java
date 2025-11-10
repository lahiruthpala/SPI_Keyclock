package org.keycloak.broker.aiesec;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class AiesecIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public AiesecIdentityProviderConfig() {
        super();
    }

    public AiesecIdentityProviderConfig(IdentityProviderModel model) {
        super(model);

        // Set default AIESEC endpoints if not configured
        if (getAuthorizationUrl() == null) {
            setAuthorizationUrl("https://auth.aiesec.org/oauth/authorize");
        }
        if (getTokenUrl() == null) {
            setTokenUrl("https://auth.aiesec.org/oauth/token");
        }
    }

    public String getClientId() {
        return getConfig().get("clientId");
    }

    public String getClientSecret() {
        return getConfig().get("clientSecret");
    }
}