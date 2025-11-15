package org.keycloak.broker.aiesec;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.*;
import org.jboss.logging.Logger;

/**
 * Handler for post-authentication callback to store AIESEC tokens
 */
public class AiesecIdentityProviderCallback {

    private static final Logger logger = Logger.getLogger(AiesecIdentityProviderCallback.class);

    public static void storeTokens(KeycloakSession session, RealmModel realm,
                                   UserModel user, BrokeredIdentityContext context,
                                   String authorizationCode, AiesecIdentityProviderConfig config) {

        logger.debugf("storeTokens called for user=%s realm=%s codeProvided=%b", user == null ? "null" : user.getUsername(), realm == null ? "null" : realm.getName(), authorizationCode != null && !authorizationCode.isEmpty());

        if (authorizationCode == null || authorizationCode.isEmpty()) {
            logger.warn("No authorization code provided to storeTokens");
            return;
        }

        try {
            // Exchange authorization code for tokens
            JsonNode tokenResponse = SimpleHttp.doPost(AiesecIdentityProvider.TOKEN_URL, session)
                    .param("grant_type", "authorization_code")
                    .param("code", authorizationCode)
                    .param("client_id", config.getClientId())
                    .param("client_secret", config.getClientSecret())
                    .asJson();

            logger.debugf("AIESEC token response: %s", tokenResponse == null ? "null" : tokenResponse.toString());

            String accessToken = tokenResponse.path("access_token").asText();
            String refreshToken = tokenResponse.path("refresh_token").asText();
            long expiresIn = tokenResponse.path("expires_in").asLong(3600);

            logger.debugf("Parsed tokens - accessToken present=%b refreshToken present=%b expiresIn=%d", accessToken != null && !accessToken.isEmpty(), refreshToken != null && !refreshToken.isEmpty(), expiresIn);

            if (accessToken == null || accessToken.isEmpty()) {
                logger.error("Failed to obtain AIESEC access token from token response");
                throw new IdentityBrokerException("Failed to obtain AIESEC access token");
            }

            // Calculate expiration timestamp
            long expiresAt = (System.currentTimeMillis() / 1000) + expiresIn;

            // Store tokens in user attributes
            user.setSingleAttribute("aiesec_access_token", accessToken);
            user.setSingleAttribute("aiesec_token_expires_at", String.valueOf(expiresAt));
            logger.debugf("Stored aiesec_access_token and aiesec_token_expires_at for user=%s", user.getUsername());
            // Also store refresh token in user attribute so protocol mappers can include it in tokens
            if (refreshToken != null && !refreshToken.isEmpty()) {
                user.setSingleAttribute("aiesec_refresh_token", refreshToken);
                logger.debugf("Stored aiesec_refresh_token for user=%s", user.getUsername());
            }

            // Update federated identity with refresh token
            FederatedIdentityModel federatedIdentity = session.users()
                    .getFederatedIdentity(realm, user, AiesecIdentityProviderFactory.PROVIDER_ID);

            logger.debugf("Federated identity fetched: %s", federatedIdentity == null ? "null" : "exists");

            if (federatedIdentity != null && refreshToken != null && !refreshToken.isEmpty()) {
                federatedIdentity.setToken(refreshToken);
                session.users().updateFederatedIdentity(realm, user, federatedIdentity);
                logger.debugf("Updated federated identity token for user=%s", user.getUsername());
            }

        } catch (Exception e) {
            logger.error("Failed to store AIESEC tokens", e);
            throw new IdentityBrokerException("Failed to store AIESEC tokens", e);
        }
    }

    public static void refreshAndStoreTokens(KeycloakSession session, RealmModel realm,
                                             UserModel user, AiesecIdentityProviderConfig config) {

        logger.debugf("refreshAndStoreTokens called for user=%s realm=%s", user == null ? "null" : user.getUsername(), realm == null ? "null" : realm.getName());

        FederatedIdentityModel federatedIdentity = session.users()
                .getFederatedIdentity(realm, user, AiesecIdentityProviderFactory.PROVIDER_ID);

        logger.debugf("Federated identity for refresh: %s", federatedIdentity == null ? "null" : "exists");

        if (federatedIdentity == null) {
            logger.warn("No federated identity found for AIESEC when attempting refresh");
            return;
        }

        String refreshToken = federatedIdentity.getToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.warnf("No refresh token stored in federated identity for user=%s", user.getUsername());
            return;
        }

        try {
            // Refresh the token
            JsonNode tokenResponse = SimpleHttp.doPost(AiesecIdentityProvider.TOKEN_URL, session)
                    .param("grant_type", "refresh_token")
                    .param("refresh_token", refreshToken)
                    .param("client_id", config.getClientId())
                    .param("client_secret", config.getClientSecret())
                    .asJson();

            logger.debugf("AIESEC refresh token response: %s", tokenResponse == null ? "null" : tokenResponse.toString());

            String newAccessToken = tokenResponse.path("access_token").asText();
            String newRefreshToken = tokenResponse.path("refresh_token").asText();
            long expiresIn = tokenResponse.path("expires_in").asLong(3600);

            logger.debugf("Parsed refreshed tokens - newAccessToken present=%b newRefreshToken present=%b expiresIn=%d", newAccessToken != null && !newAccessToken.isEmpty(), newRefreshToken != null && !newRefreshToken.isEmpty(), expiresIn);

            if (newAccessToken != null && !newAccessToken.isEmpty()) {
                long expiresAt = (System.currentTimeMillis() / 1000) + expiresIn;

                // Update stored tokens
                user.setSingleAttribute("aiesec_access_token", newAccessToken);
                user.setSingleAttribute("aiesec_token_expires_at", String.valueOf(expiresAt));
                logger.debugf("Updated stored aiesec_access_token and expires for user=%s", user.getUsername());

                // Update refresh token if provided
                if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
                    // persist refresh token also on user attributes
                    user.setSingleAttribute("aiesec_refresh_token", newRefreshToken);
                    federatedIdentity.setToken(newRefreshToken);
                    session.users().updateFederatedIdentity(realm, user, federatedIdentity);
                    logger.debugf("Updated federated identity and stored aiesec_refresh_token for user=%s", user.getUsername());
                }
            }

        } catch (Exception e) {
            // Log error but don't fail
            logger.error("Failed to refresh AIESEC token", e);
        }
    }
}