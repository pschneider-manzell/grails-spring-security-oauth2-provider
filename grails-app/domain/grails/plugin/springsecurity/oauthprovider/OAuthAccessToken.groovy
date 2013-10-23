package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessToken

class OAuthAccessToken {

    String tokenId
    Date expiration
    String tokenType
    String scope
    byte[] authentication
    String refreshToken
    String username
    String clientId
    String authenticationId

    Date dateCreated

    static constraints = {
        tokenId blank: false, nullable: false, unique: true
        refreshToken nullable: true
        authentication maxSize: 1024*5 // 5kb
        authenticationId blank: false
    }

    static mapping = {
        version false
    }

    def populateScope(scopeSet) {
        def scopeString = ""
        scopeSet?.each { scope ->
            scopeString += scope + " "
        }
        this.scope = scopeString.trim()
    }

    OAuth2AccessToken toToken() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenId)
        token.expiration = expiration
        token.tokenType = tokenType
        if (refreshToken) {
            token.refreshToken = OAuthRefreshToken.findByTokenId(refreshToken)?.toToken()
        }

        def scopeSet = new HashSet<String>();
        scope?.split()?.each { scopePart ->
            scopeSet.add scopePart
        }
        token.scope = scopeSet
        token
    }
}
