package org.keycloak.broker.aiesec;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.*;
import org.jboss.logging.Logger;

/**
 * Utility class to handle token refresh logic.
 * This is called by the AiesecTokenMapper when an access token is expired.
 */
public class AiesecIdentityProviderCallback {

    private static final Logger logger = Logger.getLogger(AiesecIdentityProviderCallback.class);

    /**
     * Refreshes the AIESEC tokens and stores the new ones on the user and federated identity.
     * This method is synchronized to prevent multiple concurrent refresh attempts for the same user.
     *
     * @return The new access_token.
     */
    public static synchronized String refreshAndStoreTokens(KeycloakSession session, RealmModel realm,
                                                            UserModel user, IdentityProviderModel idpModel) {

        logger.infof("refreshAndStoreTokens called for user=%s", user.getUsername());

        String refreshToken = user.getFirstAttribute("aiesec_refresh_token");
        if (refreshToken == null || refreshToken.isEmpty()) {
            // Fallback: Check the federated identity token
            FederatedIdentityModel federatedIdentity = session.users()
                    .getFederatedIdentity(realm, user, idpModel.getAlias());
            if (federatedIdentity != null) {
                refreshToken = federatedIdentity.getToken();
            }
        }

        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.warnf("No AIESEC refresh token found for user=%s. Refresh failed.", user.getUsername());
            throw new IdentityBrokerException("No refresh token available to refresh AIESEC session.");
        }

        AiesecIdentityProviderConfig config = new AiesecIdentityProviderConfig(idpModel);

        try {
            // Refresh the token
            JsonNode tokenResponse = SimpleHttp.doPost(config.getTokenUrl(), session)
                    .param("grant_type", "refresh_token")
                    .param("refresh_token", refreshToken)
                    .param("client_id", config.getClientId())
                    .param("client_secret", config.getClientSecret())
                    .asJson();

            logger.infof("AIESEC refresh token response: %s", tokenResponse);

            String newAccessToken = tokenResponse.path("access_token").asText(null);
            String newRefreshToken = tokenResponse.path("refresh_token").asText(null);
            long expiresIn = tokenResponse.path("expires_in").asLong(3600); // Default to 1 hour

            if (newAccessToken == null) {
                logger.errorf("Failed to refresh AIESEC token for user=%s. Response: %s",
                        user.getUsername(), tokenResponse);
                throw new IdentityBrokerException("Failed to refresh AIESEC token. Invalid response.");
            }

            long expiresAt = (System.currentTimeMillis() / 1000) + expiresIn;

            // --- Update stored tokens ---
            user.setSingleAttribute("aiesec_access_token", newAccessToken);
            user.setSingleAttribute("aiesec_token_expires_at", String.valueOf(expiresAt));
            logger.debugf("Updated user attributes with new AIESEC access token for user=%s", user.getUsername());

            if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
                user.setSingleAttribute("aiesec_refresh_token", newRefreshToken);

                // Update the federated identity (Keycloak's persistent store)
                FederatedIdentityModel federatedIdentity = session.users()
                        .getFederatedIdentity(realm, user, idpModel.getAlias());

                if (federatedIdentity != null) {
                    federatedIdentity.setToken(newRefreshToken);
                    session.users().updateFederatedIdentity(realm, user, federatedIdentity);
                    logger.debugf("Updated federated identity with new AIESEC refresh token for user=%s", user.getUsername());
                }
            }

            return newAccessToken;

        } catch (Exception e) {
            logger.errorf(e, "Failed to refresh AIESEC token for user=%s", user.getUsername());
            throw new IdentityBrokerException("Failed to refresh AIESEC token.", e);
        }
    }
}