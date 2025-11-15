package org.keycloak.broker.aiesec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

public class AiesecIdentityProvider extends AbstractOAuth2IdentityProvider<AiesecIdentityProviderConfig>
        implements SocialIdentityProvider<AiesecIdentityProviderConfig> {

    public static final String DEFAULT_SCOPE = "";
    public static final String AUTH_URL = "https://auth.aiesec.org/oauth/authorize";
    public static final String TOKEN_URL = "https://auth.aiesec.org/oauth/token";
    private static final String GRAPHQL_URL = "https://gis-api.aiesec.org/graphql";

    // Local constant for refresh token parameter name
    private static final String REFRESH_TOKEN_PARAMETER = "refresh_token";

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
        uriBuilder.replaceQueryParam("scope", (Object[]) null);
        return uriBuilder;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode payload = mapper.createObjectNode();
        payload.put("query", "query { currentPerson { id email first_name last_name profile_photo current_status current_office { id } } }");

        try {
            logger.infof("AIESEC GraphQL request with token: %s...", accessToken.substring(0, 10));
            logger.infof("AIESEC GraphQL payload: %s", payload.toString());

            JsonNode response = SimpleHttp.doPost(GRAPHQL_URL, session)
                    .header("authorization", accessToken)
                    .header("Content-Type", "application/json")
                    .json(payload)
                    .asJson();

            JsonNode person = response.path("data").path("currentPerson");
            if (person.isMissingNode() || person.path("id").isMissingNode()) {
                logger.error("Invalid GraphQL response: " + response.toPrettyString());
                throw new RuntimeException("AIESEC GraphQL: missing currentPerson");
            }

            BrokeredIdentityContext context = extractIdentityFromProfile(null, person);

            // Store tokens in context - these will be saved to FederatedIdentityModel
            context.getContextData().put("AIESEC_ACCESS_TOKEN", accessToken);
            context.setToken(accessToken);  // This stores in federated identity

            logger.infof("Context: %s", context.getContextData().toString());

            return context;
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

    protected Response exchangeExternalToken(String authorizationCode) {
        // Exchange authorization code for AIESEC tokens
        return exchangeStoredToken(session, authorizationCode);
    }

    // Helper to exchange an authorization code for tokens. Not an override.
    public Response exchangeStoredToken(KeycloakSession session, String authorizationCode) {
        try {
            JsonNode tokenResponse = SimpleHttp.doPost(TOKEN_URL, session)
                    .param("grant_type", "authorization_code")
                    .param("code", authorizationCode)
                    // redirect_uri is optional for this provider; remove call to non-existent getRedirectUri()
                    .param("client_id", getConfig().getClientId())
                    .param("client_secret", getConfig().getClientSecret())
                    .asJson();

            return Response.ok(tokenResponse).build();
        } catch (Exception e) {
            logger.error("Failed to exchange AIESEC token", e);
            throw new IdentityBrokerException("Could not exchange AIESEC token", e);
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return exchangeStoredToken(session, identity.getToken());
    }

    @Override
    protected String extractTokenFromResponse(String response, String tokenName) {
        logger.infof("Inside the extractTokenFromResponse");
        if (response == null) return null;

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node = mapper.readTree(response);

            if (tokenName.equals(OAUTH2_PARAMETER_ACCESS_TOKEN)) {
                return node.path("access_token").asText(null);
            } else if (tokenName.equals(REFRESH_TOKEN_PARAMETER)) {
                return node.path("refresh_token").asText(null);
            }

            return node.path(tokenName).asText(null);
        } catch (Exception e) {
            logger.warn("Unable to extract token from response", e);
            return null;
        }
    }

    // Not an override - used by mapping/refresh logic
    public Response refreshTokens(KeycloakSession session, UserModel user, FederatedIdentityModel federatedIdentity) {
        String refreshToken = federatedIdentity.getToken();

        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.warn("No refresh token available for AIESEC user: " + user.getUsername());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No refresh token available")
                    .build();
        }

        try {
            logger.infof("Refreshing AIESEC token for user: %s", user.getUsername());

            JsonNode tokenResponse = SimpleHttp.doPost(TOKEN_URL, session)
                    .param("grant_type", "refresh_token")
                    .param("refresh_token", refreshToken)
                    .param("client_id", getConfig().getClientId())
                    .param("client_secret", getConfig().getClientSecret())
                    .asJson();

            String newAccessToken = tokenResponse.path("access_token").asText();
            String newRefreshToken = tokenResponse.path("refresh_token").asText();
            long expiresIn = tokenResponse.path("expires_in").asLong(3600);

            if (newAccessToken == null || newAccessToken.isEmpty()) {
                throw new IdentityBrokerException("Invalid token response from AIESEC");
            }

            // Update the stored refresh token in federated identity if provided
            if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
                federatedIdentity.setToken(newRefreshToken);
            }

            // Persist federated identity update via UserProvider
            session.users().updateFederatedIdentity(session.getContext().getRealm(), user, federatedIdentity);

            // Store access token and expiry in user attributes for mappers/frontend
            long expiresAtSeconds = (System.currentTimeMillis() / 1000) + expiresIn;
            user.setSingleAttribute("aiesec_access_token", newAccessToken);
            user.setSingleAttribute("aiesec_token_expires_at", String.valueOf(expiresAtSeconds));

            logger.infof("Successfully refreshed AIESEC token for user: %s", user.getUsername());

            return Response.ok(tokenResponse).build();
        } catch (Exception e) {
            logger.error("Failed to refresh AIESEC token for user: " + user.getUsername(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Failed to refresh token: " + e.getMessage())
                    .build();
        }
    }
}