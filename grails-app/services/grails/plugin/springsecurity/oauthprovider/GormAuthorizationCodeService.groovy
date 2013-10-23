package grails.plugin.springsecurity.oauthprovider

import grails.transaction.Transactional
import org.springframework.security.oauth2.common.util.SerializationUtils
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices

@Transactional
class GormAuthorizationCodeService extends RandomValueAuthorizationCodeServices{



    @Override
    protected void store(String code, AuthorizationRequestHolder authentication) {
        def oAuthCode = new OAuthCode(
                code: code,
                authentication: SerializationUtils.serialize(authentication)
        )
        log.warn("Size of authentication: "+oAuthCode.authentication.length+" bytes")
        OAuthCode.withTransaction { status ->
            oAuthCode.save(failOnError: true)
        }
    }

    @Override
    protected AuthorizationRequestHolder remove(String code) {
        def oAuthCode = OAuthCode.findByCode code
        AuthorizationRequestHolder authentication = null
        if (oAuthCode) {
            try {
                authentication = SerializationUtils.deserialize(oAuthCode.authentication)
            } catch (RuntimeException e) {
                log.error "Failed to deserialize authentication for code: $code"
                log.error e
            }
            OAuthCode.withTransaction { status ->
                oAuthCode.delete()
            }
        }
        authentication
    }
}
