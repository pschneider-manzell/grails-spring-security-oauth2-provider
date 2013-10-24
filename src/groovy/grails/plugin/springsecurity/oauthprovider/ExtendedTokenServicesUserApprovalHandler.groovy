package grails.plugin.springsecurity.oauthprovider

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.approval.TokenServicesUserApprovalHandler
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices
import org.springframework.util.Assert

/**
 * @author Peter Schneider-Manzell
 */
class ExtendedTokenServicesUserApprovalHandler  implements UserApprovalHandler, InitializingBean {

    private static Log logger = LogFactory.getLog(TokenServicesUserApprovalHandler.class);

    private String approvalParameter = AuthorizationRequest.USER_OAUTH_APPROVAL;
    public static final String SKIP_APPROVAL = "skipApproval";

    /**
     * @param approvalParameter the approvalParameter to set
     */
    public void setApprovalParameter(String approvalParameter) {
        this.approvalParameter = approvalParameter;
    }

    private AuthorizationServerTokenServices tokenServices;
    private ClientDetailsService clientDetailsService;

    void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }
/**
     * @param tokenServices the token services to set
     */
    public void setTokenServices(AuthorizationServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public void afterPropertiesSet() {
        Assert.state(tokenServices != null, "AuthorizationServerTokenServices must be provided");
        Assert.state(clientDetailsService != null, "ClientDetailsService must be provided");
    }

    public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        return authorizationRequest;
    }

    /**
     * Basic implementation just requires the authorization request to be explicitly approved and the user to be
     * authenticated.
     *
     * @param authorizationRequest The authorization request.
     * @param userAuthentication the current user authentication
     *
     * @return Whether the specified request has been approved by the current user.
     */
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {

        String flag = authorizationRequest.getApprovalParameters().get(approvalParameter);
        boolean approved = flag != null && flag.toLowerCase().equals("true");

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
        if (logger.isDebugEnabled()) {
            StringBuilder builder = new StringBuilder("Looking up existing token for ");
            builder.append("client_id=" + authorizationRequest.getClientId());
            builder.append(", scope=" + authorizationRequest.getScope());
            builder.append(" and username=" + userAuthentication.getName());
            logger.debug(builder.toString());
        }

        if(authorizationRequest.clientId) {
            logger.debug("Loading client details for client "+authorizationRequest.clientId)
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(authorizationRequest.clientId)
            Boolean skipApproval = clientDetails.additionalInformation?.get(SKIP_APPROVAL)
            logger.debug("Skip approval for client "+authorizationRequest.clientId+"? "+skipApproval)
            if(skipApproval){
                approved = true
            }
            if(approved){
                return  approved
            }
        }

        OAuth2AccessToken accessToken = tokenServices.getAccessToken(authentication);
        logger.debug("Existing access token=" + accessToken);
        if (accessToken != null && !accessToken.isExpired()) {
            logger.debug("User already approved with token=" + accessToken);
            // A token was already granted and is still valid, so this is already approved
            approved = true;
        }
        else {
            logger.debug("Checking explicit approval");
            approved = userAuthentication.isAuthenticated() && approved;
        }

        return approved;

    }
}
