package org.keycloak.broker.aiesec;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.*;

/**
 * Handler for post-authentication callback to store AIESEC tokens
 */
public class AiesecIdentityProviderCallback {

    public static void storeTokens(KeycloakSession session, RealmModel realm,
                                   UserModel user, BrokeredIdentityContext context,
                                   String authorizationCode, AiesecIdentityProviderConfig config) {

        if (authorizationCode == null || authorizationCode.isEmpty()) {
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

            String accessToken = tokenResponse.path("access_token").asText();
            String refreshToken = tokenResponse.path("refresh_token").asText();
            long expiresIn = tokenResponse.path("expires_in").asLong(3600);

            if (accessToken == null || accessToken.isEmpty()) {
                throw new IdentityBrokerException("Failed to obtain AIESEC access token");
            }

            // Calculate expiration timestamp
            long expiresAt = (System.currentTimeMillis() / 1000) + expiresIn;

            // Store tokens in user attributes
            user.setSingleAttribute("aiesec_access_token", accessToken);
            user.setSingleAttribute("aiesec_token_expires_at", String.valueOf(expiresAt));
            // Also store refresh token in user attribute so protocol mappers can include it in tokens
            if (refreshToken != null && !refreshToken.isEmpty()) {
                user.setSingleAttribute("aiesec_refresh_token", refreshToken);
            }

            // Update federated identity with refresh token
            FederatedIdentityModel federatedIdentity = session.users()
                    .getFederatedIdentity(realm, user, AiesecIdentityProviderFactory.PROVIDER_ID);

            if (federatedIdentity != null && refreshToken != null && !refreshToken.isEmpty()) {
                federatedIdentity.setToken(refreshToken);
                session.users().updateFederatedIdentity(realm, user, federatedIdentity);
            }

        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to store AIESEC tokens", e);
        }
    }

    public static void refreshAndStoreTokens(KeycloakSession session, RealmModel realm,
                                             UserModel user, AiesecIdentityProviderConfig config) {

        FederatedIdentityModel federatedIdentity = session.users()
                .getFederatedIdentity(realm, user, AiesecIdentityProviderFactory.PROVIDER_ID);

        if (federatedIdentity == null) {
            return;
        }

        String refreshToken = federatedIdentity.getToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
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

            String newAccessToken = tokenResponse.path("access_token").asText();
            String newRefreshToken = tokenResponse.path("refresh_token").asText();
            long expiresIn = tokenResponse.path("expires_in").asLong(3600);

            if (newAccessToken != null && !newAccessToken.isEmpty()) {
                long expiresAt = (System.currentTimeMillis() / 1000) + expiresIn;

                // Update stored tokens
                user.setSingleAttribute("aiesec_access_token", newAccessToken);
                user.setSingleAttribute("aiesec_token_expires_at", String.valueOf(expiresAt));

                // Update refresh token if provided
                if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
                    // persist refresh token also on user attributes
                    user.setSingleAttribute("aiesec_refresh_token", newRefreshToken);
                    federatedIdentity.setToken(newRefreshToken);
                    session.users().updateFederatedIdentity(realm, user, federatedIdentity);
                }
            }

        } catch (Exception e) {
            // Log error but don't fail
            System.err.println("Failed to refresh AIESEC token: " + e.getMessage());
        }
    }
}