package grails.plugin.springsecurity.oauthprovider

import grails.transaction.Transactional
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import org.springframework.security.oauth2.common.util.SerializationUtils
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator
import org.springframework.security.oauth2.provider.token.TokenStore

@Transactional
class GormTokenStoreService implements TokenStore{

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();


    @Override
    OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.value)
    }

    @Override
    OAuth2Authentication readAuthentication(String accessToken) {
        OAuthAccessToken persistentAccessToken = OAuthAccessToken.findByTokenId accessToken
        OAuth2Authentication authentication = null
        if (persistentAccessToken) {
            try {
                authentication = deserializeAuthentication(persistentAccessToken.authentication)
            } catch (RuntimeException e) {
                log.error "Failed to deserialize authentication for token: $accessToken"
                log.error e
            }
        } else {
            log.info "Failed to find access token for token: $accessToken"
        }
        authentication
    }

    @Override
    void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        def accessToken = new OAuthAccessToken(
                tokenId: token.value,
                expiration: token.expiration,
                tokenType: token.tokenType,
                authentication: serializeAuthentication(authentication),
                refreshToken: token.refreshToken?.value,
                username: authentication.name,
                clientId: authentication.clientAuthentication.clientId,
                authenticationId: authenticationKeyGenerator.extractKey(authentication)
        )
        accessToken.populateScope(token.scope)
        OAuthAccessToken.withTransaction { status ->
            accessToken.save(failOnError: true)
        }
    }

    @Override
    OAuth2AccessToken readAccessToken(String tokenValue) {
        def accessToken = OAuthAccessToken.findByTokenId tokenValue
        def token = null
        if (accessToken) {
            log.debug "Found access token for token: $tokenValue"
            token = accessToken.toToken()
        } else {
            log.info "Failed to find access token for token: $tokenValue"
        }
        token
    }

    @Override
    void removeAccessToken(OAuth2AccessToken token) {
        def accessToken = OAuthAccessToken.findByTokenId token.value
        if (accessToken) {
            OAuthAccessToken.withTransaction { status ->
                accessToken.delete()
            }
        }
    }

    @Override
    void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        def storedRefreshToken = new OAuthRefreshToken(
                tokenId: refreshToken.value,
                authentication: serializeAuthentication(authentication),
                username: authentication.name
        )
        if(refreshToken instanceof ExpiringOAuth2RefreshToken){
            storedRefreshToken.expiration = ((ExpiringOAuth2RefreshToken)refreshToken).expiration
        }
        OAuthRefreshToken.withTransaction { status ->
            storedRefreshToken.save()
        }
    }

    @Override
    OAuth2RefreshToken readRefreshToken(String tokenValue) {
        def refreshToken = OAuthRefreshToken.findByTokenId tokenValue
        OAuth2RefreshToken token = null
        if (refreshToken) {
            log.debug "Found refresh token for token: $tokenValue"
            token = refreshToken.toToken()
        } else {
            log.info "Failed to find refresh token for token: $tokenValue"
        }
        token
    }

    @Override
    OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        OAuthRefreshToken refreshToken = readRefreshToken(token.value)
        OAuth2Authentication authentication = null
        if (refreshToken) {
            try {
                authentication = deserializeAuthentication(refreshToken.authentication)
            } catch (RuntimeException e) {
                log.error "Failed to deserialize authentication for refresh token: $token"
                log.error e
            }
        } else {
            log.info "Failed to find access token for refresh token: $token"
        }
        authentication
    }

    @Override
    void removeRefreshToken(OAuth2RefreshToken token) {
        OAuthRefreshToken refreshToken = OAuthRefreshToken.findByTokenId token.value
        if (refreshToken) {
            OAuthRefreshToken.withTransaction { status ->
                refreshToken.delete()
            }
        }
    }

    @Override
    void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        OAuthAccessToken accessToken = OAuthAccessToken.findByRefreshToken refreshToken.value
        if (accessToken) {
            OAuthAccessToken.withTransaction { status ->
                accessToken.delete()
            }
        }
    }

    @Override
    OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuthAccessToken persistentAccessToken = OAuthAccessToken.findByAuthenticationId(authenticationKeyGenerator.extractKey(authentication))
        OAuth2AccessToken accessToken
        if(persistentAccessToken){
            accessToken =  deserializeAuthentication(persistentAccessToken.authentication)
        }
        return accessToken
    }

    @Override
    Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
        return OAuthAccessToken.findAllByUsername(userName)
    }

    @Override
    Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        return OAuthAccessToken.findAllByClientId(clientId)
    }

    protected byte[] serializeAccessToken(OAuth2AccessToken token) {
        return SerializationUtils.serialize(token);
    }

    protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
        return SerializationUtils.serialize(token);
    }

    protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
        return SerializationUtils.serialize(authentication);
    }

    protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
        return SerializationUtils.deserialize(token);
    }

    protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
        return SerializationUtils.deserialize(token);
    }

    protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
        return SerializationUtils.deserialize(authentication);
    }
}
