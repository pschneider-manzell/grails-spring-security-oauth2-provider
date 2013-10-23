package grails.plugin.springsecurity.oauthprovider

import grails.transaction.Transactional
import org.springframework.dao.DuplicateKeyException
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.security.oauth2.provider.ClientRegistrationService
import org.springframework.security.oauth2.provider.NoSuchClientException
import org.springframework.util.StringUtils
import org.codehaus.jackson.map.ObjectMapper;

@Transactional
class GormClientDetailsService implements  ClientDetailsService,ClientRegistrationService{

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

    @Override
    void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        OAuthClient persistentClient = OAuthClient.findByClientId clientDetails.clientId
        if(!persistentClient){
            throw new NoSuchClientException("No client with requested id: " + clientDetails.clientId)
        }
        OAuthClient convertedDetails = convert(clientDetails)
        persistentClient.resourceIds=convertedDetails.resourceIds
        persistentClient.scopes=convertedDetails.scopes
        persistentClient.redirectUris=convertedDetails.redirectUris
        persistentClient.authorities=convertedDetails.authorities
        persistentClient.grantTypes=convertedDetails.grantTypes
        persistentClient.additionalInformations=convertedDetails.additionalInformations
        persistentClient.accessTokenValiditySeconds=convertedDetails.accessTokenValiditySeconds
        persistentClient.refreshTokenValiditySeconds=convertedDetails.refreshTokenValiditySeconds
        persistentClient.save(failOnError: true)
    }

    @Override
    void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        OAuthClient persistentClient = OAuthClient.findByClientId clientId
        if(!persistentClient){
            throw new NoSuchClientException("No client with requested id: " + clientId)
        }
        persistentClient.clientSecret = secret
        persistentClient.save(failOnError: true)
    }

    @Override
    void removeClientDetails(String clientId) throws NoSuchClientException {
        OAuthClient persistentClient = OAuthClient.findByClientId clientId
        if(!persistentClient){
            throw new NoSuchClientException("No client with requested id: " + clientId)
        }
        persistentClient.delete()
    }

    @Override
    List<ClientDetails> listClientDetails() {
        List<ClientDetails> result = []
        OAuthClient.list().each {OAuthClient client->
            result.add(client.toClientDetails())
        }
        return result
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
