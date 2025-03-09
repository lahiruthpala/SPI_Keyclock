package org.keycloak.broker.aiesec;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;

import java.util.ArrayList;
import java.util.List;

public class AiesecIdentityProviderFactory extends AbstractIdentityProviderFactory<AiesecIdentityProvider>
        implements SocialIdentityProviderFactory<AiesecIdentityProvider> {

    public static final String PROVIDER_ID = "aiesec";
    public static final String PROVIDER_NAME = "AIESEC";

    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public AiesecIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new AiesecIdentityProvider(session, new AiesecIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AiesecIdentityProviderConfig createConfig() {
        return new AiesecIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty clientId = new ProviderConfigProperty();
        clientId.setName(CLIENT_ID);
        clientId.setLabel("Client ID");
        clientId.setHelpText("The client ID from your AIESEC application");
        clientId.setType(ProviderConfigProperty.STRING_TYPE);
        clientId.setRequired(true);
        configProperties.add(clientId);

        ProviderConfigProperty clientSecret = new ProviderConfigProperty();
        clientSecret.setName(CLIENT_SECRET);
        clientSecret.setLabel("Client Secret");
        clientSecret.setHelpText("The client secret from your AIESEC application");
        clientSecret.setType(ProviderConfigProperty.STRING_TYPE);
        clientSecret.setRequired(true);
        configProperties.add(clientSecret);

        return configProperties;
    }
}