package org.keycloak.broker.aiesec;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

public class AiesecTokenMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final String PROVIDER_ID = "aiesec-token-mapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

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

        UserModel user = userSession.getUser();
        RealmModel realm = userSession.getRealm();

        // Get the AIESEC federated identity
        FederatedIdentityModel federatedIdentity = keycloakSession.users()
                .getFederatedIdentity(realm, user, AiesecIdentityProviderFactory.PROVIDER_ID);

        if (federatedIdentity == null) {
            return;
        }

        // Check if token needs refresh
        boolean shouldRefresh = shouldRefreshToken(federatedIdentity);

        if (shouldRefresh) {
            // Refresh the AIESEC token
            refreshAiesecToken(keycloakSession, user, realm, federatedIdentity);
        }

        // Add AIESEC tokens to the Keycloak token claims
        String accessToken = getStoredAccessToken(user);
        String refreshToken = federatedIdentity.getToken();

        if (accessToken != null) {
            token.setOtherClaims("aiesec_access_token", accessToken);
        }

        if (refreshToken != null) {
            token.setOtherClaims("aiesec_refresh_token", refreshToken);
        }

        // Add token expiration info if available
        Long expiresAt = getTokenExpirationTime(federatedIdentity);
        if (expiresAt != null) {
            token.setOtherClaims("aiesec_token_expires_at", expiresAt);
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
                return;
            }

            long expiresAt = Long.parseLong(expiresAtStr);
            long currentTime = System.currentTimeMillis() / 1000;

            // Only refresh if token expires in less than 5 minutes
            if ((expiresAt - currentTime) >= 300) {
                return;
            }

            // Get the identity provider config
            IdentityProviderModel providerModel = realm.getIdentityProviderByAlias(
                    AiesecIdentityProviderFactory.PROVIDER_ID);

            if (providerModel == null) {
                return;
            }

            AiesecIdentityProviderConfig config = new AiesecIdentityProviderConfig(providerModel);

            // Use callback handler to refresh tokens
            AiesecIdentityProviderCallback.refreshAndStoreTokens(session, realm, user, config);

        } catch (Exception e) {
            // Log but don't fail the token generation
            System.err.println("Failed to refresh AIESEC token: " + e.getMessage());
        }
    }

    private String getStoredAccessToken(UserModel user) {
        // Get access token from user attributes
        return user.getFirstAttribute("aiesec_access_token");
    }
}