package org.keycloak.broker.aiesec;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

public class AiesecIdentityProvider extends AbstractOAuth2IdentityProvider<AiesecIdentityProviderConfig>
        implements SocialIdentityProvider<AiesecIdentityProviderConfig> {

    public static final String DEFAULT_SCOPE = "openid profile email";
    public static final String AUTH_URL = "https://auth.aiesec.org/oauth/authorize";
    public static final String TOKEN_URL = "https://auth.aiesec.org/oauth/token";

    public AiesecIdentityProvider(KeycloakSession session, AiesecIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request){
        final UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        uriBuilder.replaceQueryParam("state", (Object[]) null);
        uriBuilder.replaceQueryParam("scope", (Object[]) null);
        return uriBuilder;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), session)
                    .header("Authorization", "Bearer " + accessToken)
                    .asJson();

            return extractIdentityFromProfile(null, profile);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get user info from AIESEC", e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(
                getJsonProperty(profile, "id"),
                getConfig());

        user.setUsername(getJsonProperty(profile, "email"));
        user.setEmail(getJsonProperty(profile, "email"));
        user.setFirstName(getJsonProperty(profile, "first_name"));
        user.setLastName(getJsonProperty(profile, "last_name"));

        // Set additional attributes if available
        user.setUserAttribute("aiesec_id", getJsonProperty(profile, "id"));

        return user;
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        return tokenRequest.param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                .param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret());
    }
}