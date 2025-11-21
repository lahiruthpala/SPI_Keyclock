package org.keycloak.broker.aiesec;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.jboss.logging.Logger;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.models.IdentityProviderModel;

public class AiesecTokenMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final String PROVIDER_ID = "aiesec-token-mapper";
    private static final long EXPIRATION_BUFFER_SECONDS = 300;
    private static final Logger logger = Logger.getLogger(AiesecTokenMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, AiesecTokenMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        logger.infof("getDisplayCategory() called");
        String cat = TOKEN_MAPPER_CATEGORY;
        logger.infof("getDisplayCategory returning: %s", cat);
        return cat;
    }

    @Override
    public String getDisplayType() {
        logger.infof("getDisplayType() called");
        String t = "AIESEC Token Mapper";
        logger.infof("getDisplayType returning: %s", t);
        return t;
    }

    @Override
    public String getHelpText() {
        logger.infof("getHelpText() called");
        String help = "Injects AIESEC access token into Keycloak tokens";
        logger.infof("getHelpText returning: %s", help);
        return help;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        logger.infof("getConfigProperties() called - configProperties size: %d", configProperties.size());
        return configProperties;
    }

    @Override
    public String getId() {
        logger.infof("getId() called - PROVIDER_ID: %s", PROVIDER_ID);
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        logger.infof("setClaim() called with token=%s, mappingModel=%s, userSession=%s, keycloakSession=%s, clientSessionCtx=%s",
                token, mappingModel, userSession, keycloakSession, clientSessionCtx);

        if (userSession == null) {
            logger.infof("userSession is null - exiting setClaim");
            return;
        }

        UserModel user = userSession.getUser();
        RealmModel realm = userSession.getRealm();
        logger.infof("setClaim - resolved user=%s, realm=%s", user, realm);

        // Get the alias of the IdP the user *actually* used to log in (e.g., "aiesec-login")
        String idpAlias = userSession.getNote("identity_provider");

        if (idpAlias == null) {
            logger.infof("User did not log in via an IdP (idpAlias is null). Skipping mapper.");
            return;
        }

        // Get the configuration model for that IdP
        IdentityProviderModel idpModel = realm.getIdentityProviderByAlias(idpAlias);
        if (idpModel == null) {
            logger.infof("Could not find IdP model for alias: %s", idpAlias);
            return;
        }

        // Check if the IdP they used is *our* AIESEC provider
        if (!AiesecIdentityProviderFactory.PROVIDER_ID.equals(idpModel.getProviderId())) {
            logger.infof("User logged in with IdP '%s', but it is not an AIESEC provider (its providerId is '%s'). Skipping.",
                    idpAlias, idpModel.getProviderId());
            return;
        }

        // --- DEBUG: Log all user attributes ---
        logger.infof("--- DUMPING ATTRIBUTES FOR USER: %s ---", user.getUsername());
        java.util.Map<String, java.util.List<String>> attributes = user.getAttributes();
        if (attributes == null || attributes.isEmpty()) {
            logger.infof("User has no attributes.");
        } else {
            for (java.util.Map.Entry<String, java.util.List<String>> entry : attributes.entrySet()) {
                String key = entry.getKey();
                java.util.List<String> values = entry.getValue();
                // Log the key and the list of values (attributes can have multiple values)
                logger.infof("  ATTR [%s]: %s", key, values);
            }
        }
        logger.infof("--- END OF ATTRIBUTE DUMP ---");

        // --- Refresh Logic Starts Here ---
        String accessToken = user.getFirstAttribute("aiesec_access_token");
        String refreshToken = user.getFirstAttribute("aiesec_refresh_token");
        String expiresAtStr = user.getFirstAttribute("aiesec_token_expires_at");

        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.warnf("User %s has no AIESEC refresh token. Cannot check for refresh.", user.getUsername());
            // We can still try to inject the access token if it exists
        } else if (expiresAtStr == null) {
            logger.warnf("User %s has no 'aiesec_token_expires_at' attribute. Cannot check for refresh.", user.getUsername());
        } else {
            try {
                long expiresAt = Long.parseLong(expiresAtStr);
                long now = System.currentTimeMillis() / 1000;

                // Check if (expiration - 5 minutes) is already in the past
                if ((expiresAt - EXPIRATION_BUFFER_SECONDS) <= now) {
                    logger.infof("AIESEC access token for user %s is expired or expiring soon. Attempting refresh.", user.getUsername());

                    // Call the callback to perform the refresh
                    accessToken = AiesecIdentityProviderCallback.refreshAndStoreTokens(keycloakSession, realm, user, idpModel);

                    logger.infof("AIESEC token refresh successful for user %s.", user.getUsername());
                } else {
                    logger.infof("AIESEC access token for user %s is still valid.", user.getUsername());
                }

            } catch (NumberFormatException e) {
                logger.warnf(e, "Could not parse 'aiesec_token_expires_at' for user %s. Value was: %s", user.getUsername(), expiresAtStr);
            } catch (Exception e) {
                // This catches a failed refresh from the callback
                logger.errorf(e, "Failed to refresh AIESEC token for user %s. Token will not be injected.", user.getUsername());
                // Do not inject any token if refresh failed, as it's likely invalid.
                return;
            }
        }

        FederatedIdentityModel federatedIdentity = keycloakSession.users()
                .getFederatedIdentity(realm, user, idpAlias);

        logger.infof("setClaim - federatedIdentity resolved (using alias '%s'): %s", idpAlias, federatedIdentity);

        if (federatedIdentity != null) {
            logger.infof("federatedIdentity is not null for user %s", user != null ? user.getUsername() : "<null-user>");
            logger.infof("retrieved accessToken (raw)=%s", accessToken);

            if (accessToken != null && !accessToken.isEmpty()) {
                logger.infof("accessToken is non-empty - injecting into token claim 'aiesec_access_token'");
                token.getOtherClaims().put("aiesec_access_token", accessToken);
                logger.infof("Successfully injected AIESEC token for user %s", user.getUsername());
            } else {
                logger.infof("AIESEC identity found but accessToken was null or empty for user %s", user.getUsername());
            }
        } else {
            logger.infof("No AIESEC federated identity found for user %s (using alias '%s')", user != null ? user.getUsername() : "<null-user>", idpAlias);
        }

        logger.infof("setClaim() completed - token otherClaims now contains: %s", token.getOtherClaims());
    }
}