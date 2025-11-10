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

    public static final String DEFAULT_SCOPE = "";
    public static final String AUTH_URL = "https://auth.aiesec.org/oauth/authorize";
    public static final String TOKEN_URL = "https://auth.aiesec.org/oauth/token";
    private static final String GRAPHQL_URL = "https://gis-api.aiesec.org/graphql";
    private static final String GRAPHQL_QUERY = "{ \"query\": \"query { currentPerson { id email first_name last_name profile_photo current_status current_office { id } } }\" }";

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
//        uriBuilder.replaceQueryParam("state", (Object[]) null);
        uriBuilder.replaceQueryParam("scope", (Object[]) null);
        return uriBuilder;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            logger.infof("AIESEC GraphQL request with token: %s...", accessToken.substring(0, 10));

            JsonNode response = SimpleHttp.doPost(GRAPHQL_URL, session)
                    .header("Authorization", accessToken)
                    .header("Content-Type", "application/json")
                    .json(GRAPHQL_QUERY)
                    .asJson();

            JsonNode person = response.path("data").path("currentPerson");
            if (person.isMissingNode() || person.path("id").isMissingNode()) {
                logger.error("Invalid GraphQL response: " + response.toPrettyString());
                throw new RuntimeException("AIESEC GraphQL: missing currentPerson");
            }

            return extractIdentityFromProfile(null, person);
        } catch (Exception e) {
            logger.error("Failed to fetch AIESEC user", e);
            throw new RuntimeException("Could not retrieve user from AIESEC", e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String id = getJsonProperty(profile, "id");
        String email = getJsonProperty(profile, "email");
        String first_name = getJsonProperty(profile, "first_name");
        String last_name = getJsonProperty(profile, "last_name");

        BrokeredIdentityContext user = new BrokeredIdentityContext(id, getConfig());
        user.setUsername(email);
        user.setEmail(email);

        user.setFirstName(first_name);
        user.setLastName(last_name);

        user.setUserAttribute("aiesec_id", id);
        user.setUserAttribute("aiesec_status", getJsonProperty(profile, "current_status"));
        user.setUserAttribute("aiesec_photo", getJsonProperty(profile, "profile_photo"));

        JsonNode office = profile.path("current_office");
        if (!office.isMissingNode()) {
            user.setUserAttribute("aiesec_office_id", getJsonProperty(office, "id"));
        }

        return user;
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        return tokenRequest
                .param("client_id", getConfig().getClientId())
                .param("client_secret", getConfig().getClientSecret());
    }
}