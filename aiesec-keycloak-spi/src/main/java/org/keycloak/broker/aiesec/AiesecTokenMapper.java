package org.keycloak.broker.aiesec;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;

public class AiesecTokenMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final String PROVIDER_ID = "aiesec-token-mapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final Logger logger = Logger.getLogger(AiesecTokenMapper.class);

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, AiesecTokenMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "AIESEC Token Mapper";
    }

    @Override
    public String getHelpText() {
        return "Injects AIESEC access token and refresh token into Keycloak tokens";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        logger.debugf("AiesecTokenMapper.setClaim called for userSession=%s client=%s", userSession == null ? "null" : userSession.getId(), clientSessionCtx == null ? "null" : clientSessionCtx.getClientSession().getClient().getClientId());

        UserModel user = userSession.getUser();
        RealmModel realm = userSession.getRealm();

        // Get the AIESEC federated identity
        FederatedIdentityModel federatedIdentity = keycloakSession.users()
                .getFederatedIdentity(realm, user, AiesecIdentityProviderFactory.PROVIDER_ID);

        if (federatedIdentity == null) {
            logger.debugf("No AIESEC federated identity for user=%s", user == null ? "null" : user.getUsername());
            return;
        }

        logger.debugf("Found AIESEC federated identity for user=%s", user.getUsername());

        // Check if token needs refresh
        boolean shouldRefresh = shouldRefreshToken(federatedIdentity);

        if (shouldRefresh) {
            logger.debugf("AIESEC token should be refreshed for user=%s", user.getUsername());
            // Refresh the AIESEC token
            refreshAiesecToken(keycloakSession, user, realm, federatedIdentity);
        }

        // Add AIESEC tokens to the Keycloak token claims
        String accessToken = getStoredAccessToken(user);
        String refreshToken = federatedIdentity.getToken();

        logger.debugf("Access token from attributes present=%b refresh token present=%b", accessToken != null, refreshToken != null);

        if (accessToken != null) {
            token.setOtherClaims("aiesec_access_token", accessToken);
            logger.debugf("Injected aiesec_access_token claim for user=%s", user.getUsername());
        }

        if (refreshToken != null) {
            token.setOtherClaims("aiesec_refresh_token", refreshToken);
            logger.debugf("Injected aiesec_refresh_token claim for user=%s", user.getUsername());
        }

        // Add token expiration info if available
        Long expiresAt = getTokenExpirationTime(federatedIdentity);
        if (expiresAt != null) {
            token.setOtherClaims("aiesec_token_expires_at", expiresAt);
            logger.debugf("Injected aiesec_token_expires_at claim=%d for user=%s", expiresAt, user.getUsername());
        }
    }

    private boolean shouldRefreshToken(FederatedIdentityModel federatedIdentity) {
        // This method is called but actual refresh happens in refreshAiesecToken
        return true; // Always check and refresh if needed
    }

    private Long getTokenExpirationTime(FederatedIdentityModel federatedIdentity) {
        // Not used anymore, kept for compatibility
        return null;
    }

    private void refreshAiesecToken(KeycloakSession session, UserModel user,
                                    RealmModel realm, FederatedIdentityModel federatedIdentity) {
        try {
            // Check if token needs refresh based on user attributes
            String expiresAtStr = user.getFirstAttribute("aiesec_token_expires_at");
            if (expiresAtStr == null || expiresAtStr.isEmpty()) {
                logger.debugf("No aiesec_token_expires_at attribute for user=%s", user.getUsername());
                return;
            }

            long expiresAt = Long.parseLong(expiresAtStr);
            long currentTime = System.currentTimeMillis() / 1000;

            // Only refresh if token expires in less than 5 minutes
            if ((expiresAt - currentTime) >= 300) {
                logger.debugf("AIESEC token for user=%s not expiring soon (expiresAt=%d current=%d)", user.getUsername(), expiresAt, currentTime);
                return;
            }

            // Get the identity provider config
            IdentityProviderModel providerModel = realm.getIdentityProviderByAlias(
                    AiesecIdentityProviderFactory.PROVIDER_ID);

            if (providerModel == null) {
                logger.warnf("No provider model found for alias=%s", AiesecIdentityProviderFactory.PROVIDER_ID);
                return;
            }

            AiesecIdentityProviderConfig config = new AiesecIdentityProviderConfig(providerModel);

            // Use callback handler to refresh tokens
            AiesecIdentityProviderCallback.refreshAndStoreTokens(session, realm, user, config);

            logger.debugf("Called refreshAndStoreTokens for user=%s", user.getUsername());

        } catch (Exception e) {
            // Log but don't fail the token generation
            logger.errorf(e, "Failed to refresh AIESEC token for user=%s", user == null ? "null" : user.getUsername());
        }
    }

    private String getStoredAccessToken(UserModel user) {
        // Get access token from user attributes
        return user.getFirstAttribute("aiesec_access_token");
    }
}