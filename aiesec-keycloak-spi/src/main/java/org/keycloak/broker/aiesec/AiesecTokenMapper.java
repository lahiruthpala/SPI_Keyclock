package org.keycloak.broker.aiesec;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.jboss.logging.Logger;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

public class AiesecTokenMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final String PROVIDER_ID = "aiesec-token-mapper";
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

        // --- THIS IS THE FIX ---
        // Look up the federated identity using the *correct alias* (idpAlias)
        // instead of the hardcoded factory ID.
        FederatedIdentityModel federatedIdentity = keycloakSession.users()
                .getFederatedIdentity(realm, user, idpAlias);

        logger.infof("setClaim - federatedIdentity resolved (using alias '%s'): %s", idpAlias, federatedIdentity);

        if (federatedIdentity != null) {
            logger.infof("federatedIdentity is not null for user %s", user != null ? user.getUsername() : "<null-user>");
            String accessToken = federatedIdentity.getToken();
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