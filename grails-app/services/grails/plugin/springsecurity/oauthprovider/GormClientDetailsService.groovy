package grails.plugin.springsecurity.oauthprovider

import grails.transaction.Transactional
import org.springframework.dao.DuplicateKeyException
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.util.StringUtils
import org.codehaus.jackson.map.ObjectMapper;

@Transactional
class GormClientDetailsService implements  ClientDetailsService{

    ObjectMapper mapper = new ObjectMapper();

    @Override
    ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        OAuthClient client = OAuthClient.findByClientId clientId
        if (client == null) {
            throw new InvalidClientException("No client with requested id: " + clientId)
        }
        log.debug "Found client details for client: $clientId"
        BaseClientDetails clientDetails = client.toClientDetails()
        if(client.additionalInformations){
            Map<String, Object> additionalInformation = mapper.readValue(client.additionalInformations, Map.class);
            clientDetails.additionalInformation = additionalInformation
        }
        return clientDetails
    }

    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        OAuthClient oAuthClient = OAuthClient.findByClientId clientDetails.clientId
        if(oAuthClient){
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId());
        }
        try {
            OAuthClient client = convert(clientDetails)
            client.save(failOnError: true)
        }
        catch (DuplicateKeyException e) {
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId(), e);
        }
    }

    private OAuthClient convert(ClientDetails clientDetails){
       String additionalInformations = null
       if(clientDetails.additionalInformation){
           try {
               additionalInformations = mapper.writeValueAsString(clientDetails.additionalInformation);
           }
           catch (Exception e) {
               log.warn("Could not serialize additional information: " + clientDetails, e);
           }
       }
       OAuthClient oAuthClient = new OAuthClient(
               clientId: clientDetails.clientId,
               clientSecret: clientDetails.clientSecret,
               resourceIds:clientDetails.resourceIds? StringUtils.collectionToCommaDelimitedString(clientDetails.resourceIds) : null,
               scopes:clientDetails.scope? StringUtils.collectionToCommaDelimitedString(clientDetails.scope) : null,
               redirectUris:clientDetails.registeredRedirectUri? StringUtils.collectionToCommaDelimitedString(clientDetails.registeredRedirectUri) : null,
               authorities:clientDetails.authorities? StringUtils.collectionToCommaDelimitedString(clientDetails.authorities):null,
               grantTypes:clientDetails.authorizedGrantTypes? StringUtils.collectionToCommaDelimitedString(clientDetails.authorizedGrantTypes):null,
               additionalInformations: additionalInformations,
               accessTokenValiditySeconds:clientDetails.accessTokenValiditySeconds,
               refreshTokenValiditySeconds:clientDetails.refreshTokenValiditySeconds,
       )
       return oAuthClient
    }
}
