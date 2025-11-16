package org.keycloak.broker.aiesec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;

public class AiesecIdentityProvider extends AbstractOAuth2IdentityProvider<AiesecIdentityProviderConfig>
        implements SocialIdentityProvider<AiesecIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(AiesecIdentityProvider.class); // Define logger
    public static final String DEFAULT_SCOPE = "";
    public static final String AUTH_URL = "https://auth.aiesec.org/oauth/authorize";
    public static final String TOKEN_URL = "https://auth.aiesec.org/oauth/token";
    private static final String GRAPHQL_URL = "https://gis-api.aiesec.org/graphql";

    public AiesecIdentityProvider(KeycloakSession session, AiesecIdentityProviderConfig config) {
        super(session, config);
        logger.infof("AiesecIdentityProvider.<init> called with session=%s, config=%s", session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        logger.infof("AiesecIdentityProvider.<init> set authorizationUrl=%s tokenUrl=%s", AUTH_URL, TOKEN_URL);
    }

    @Override
    protected String getDefaultScopes() {
        logger.infof("getDefaultScopes() called - DEFAULT_SCOPE='%s'", DEFAULT_SCOPE);
        String scopes = DEFAULT_SCOPE;
        logger.infof("getDefaultScopes() returning: %s", scopes);
        return scopes;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request){
        logger.infof("createAuthorizationUrl() called with request=%s", request);
        final UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        logger.infof("createAuthorizationUrl - before replaceQueryParam, uriBuilder=%s", uriBuilder);
        uriBuilder.replaceQueryParam("scope", (Object[]) null);
        logger.infof("createAuthorizationUrl - after replaceQueryParam, uriBuilder=%s", uriBuilder);
        return uriBuilder;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        logger.infof("doGetFederatedIdentity() called with accessToken (len)=%s",
                accessToken != null ? accessToken.length() : "<null>");
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode payload = mapper.createObjectNode();
        payload.put("query", "query { currentPerson { id email first_name last_name profile_photo current_status current_office { id } } }");

        try {
            String previewToken = "<null>";
            if (accessToken != null) {
                previewToken = accessToken.length() > 10 ? accessToken.substring(0, 10) + "..." : accessToken;
            }
            logger.infof("Fetching AIESEC identity with token preview: %s", previewToken);

            JsonNode response = SimpleHttp.doPost(GRAPHQL_URL, session)
                    .header("authorization", accessToken)
                    .header("Content-Type", "application/json")
                    .json(payload)
                    .asJson();

            logger.infof("doGetFederatedIdentity - raw GraphQL response: %s", response);

            // --- ERROR HANDLING BLOCK ---
            JsonNode person = response.path("data").path("currentPerson");

            if (response.has("error") || person.isMissingNode()) {
                String errorMessage = "Invalid AIESEC account or credentials."; // Default message

                if (response.has("message")) {
                    errorMessage = response.get("message").asText();
                } else if (response.has("error")) {
                    errorMessage = response.get("error").asText();
                }

                logger.warnf("AIESEC GraphQL API returned an error: %s", errorMessage);

                // --- THE FIX ---
                // Throw the user-facing IdentityBrokerException. Keycloak will catch this.
                throw new IdentityBrokerException(errorMessage);
            }
            // --- END OF BLOCK ---

            logger.infof("doGetFederatedIdentity - extracted person node: %s", person);

            if (person.path("id").isMissingNode()) {
                logger.warnf("AIESEC GraphQL: missing 'id' in currentPerson node.");
                // --- THE FIX ---
                throw new IdentityBrokerException("Could not parse user ID from AIESEC profile.");
            }

            BrokeredIdentityContext context = extractIdentityFromProfile(null, person);
            logger.infof("doGetFederatedIdentity - extracted BrokeredIdentityContext: %s", context);

            context.getContextData().put("AIESEC_ACCESS_TOKEN", accessToken);
            logger.infof("doGetFederatedIdentity - stored accessToken in context under 'AIESEC_ACCESS_TOKEN' (len)=%s",
                    accessToken != null ? accessToken.length() : "<null>");

            context.setToken(accessToken);
            logger.infof("doGetFederatedIdentity - context token set: %s", context.getToken());

            logger.infof("doGetFederatedIdentity - returning context: %s", context);
            return context;

        } catch (IdentityBrokerException e) {
            // --- THE FIX ---
            // Re-throw our "friendly" exception so Keycloak can handle it
            throw e;

        } catch (Exception e) {
            // This catches all other unexpected errors (e.G., network timeout)
            logger.errorf(e, "Failed to fetch AIESEC user: %s", e.getMessage());
            // We can also wrap this in an IdentityBrokerException
            throw new IdentityBrokerException("Could not retrieve user from AIESEC: " + e.getMessage(), e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        logger.infof("extractIdentityFromProfile() called with event=%s, profile=%s", event, profile);
        String id = getJsonProperty(profile, "id");
        String email = getJsonProperty(profile, "email");
        String first_name = getJsonProperty(profile, "first_name");
        String last_name = getJsonProperty(profile, "last_name");

        logger.infof("extractIdentityFromProfile - parsed fields id=%s, email=%s, first_name=%s, last_name=%s",
                id, email, first_name, last_name);

        BrokeredIdentityContext user = new BrokeredIdentityContext(id, getConfig());
        user.setUsername(email);
        user.setEmail(email);
        user.setFirstName(first_name);
        user.setLastName(last_name);

        logger.infof("extractIdentityFromProfile - created BrokeredIdentityContext user before attributes: %s", user);

        // Store specific AIESEC attributes
        user.setUserAttribute("aiesec_id", id);
        user.setUserAttribute("aiesec_status", getJsonProperty(profile, "current_status"));
        user.setUserAttribute("aiesec_photo", getJsonProperty(profile, "profile_photo"));

        logger.infof("extractIdentityFromProfile - set user attributes aiesec_id=%s, aiesec_status=%s, aiesec_photo=%s",
                id, getJsonProperty(profile, "current_status"), getJsonProperty(profile, "profile_photo"));

        JsonNode office = profile.path("current_office");
        if (!office.isMissingNode()) {
            String officeId = getJsonProperty(office, "id");
            user.setUserAttribute("aiesec_office_id", officeId);
            logger.infof("extractIdentityFromProfile - office present, set aiesec_office_id=%s", officeId);
        } else {
            logger.infof("extractIdentityFromProfile - office missing or empty: %s", office);
        }

        logger.infof("extractIdentityFromProfile - returning user context: %s", user);
        return user;
    }
}