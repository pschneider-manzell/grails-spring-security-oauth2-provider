package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientDetails

class OAuthClient {

    String clientId
    String resourceIds
    String clientSecret
    String scopes
    String redirectUris
    String authorities
    String grantTypes
    String additionalInformations
    Integer accessTokenValiditySeconds
    Integer refreshTokenValiditySeconds

    Date dateCreated

    static constraints = {
        clientId blank: false, nullable: false, unique: true
        additionalInformations nullable: true
        resourceIds nullable: true
        scopes nullable: true
        redirectUris nullable: true
        authorities nullable: true
    }

    static mapping = {
        version false
    }

    BaseClientDetails toClientDetails() {
        BaseClientDetails details = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities, redirectUris)
        details.clientSecret = clientSecret
        details.accessTokenValiditySeconds = accessTokenValiditySeconds
        details.refreshTokenValiditySeconds = refreshTokenValiditySeconds
        details
    }
}
