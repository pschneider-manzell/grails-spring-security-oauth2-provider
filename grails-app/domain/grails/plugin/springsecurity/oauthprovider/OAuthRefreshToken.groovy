package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken

class OAuthRefreshToken {

    String tokenId
    Date expiration
    byte[] authentication
    String username

    Date dateCreated

    static constraints = {
        tokenId blank: false, nullable: false, unique: true
        expiration nullable: true
        authentication maxSize: 1024*5 // 5kb
    }

    static mapping = {
        version false
    }

    OAuth2RefreshToken toToken() {
        if(expiration != null){
            return  new DefaultExpiringOAuth2RefreshToken(tokenId, expiration)
        }
        else {
            return new DefaultOAuth2RefreshToken(tokenId)
        }

    }
}
