package grails.plugin.springsecurity.oauthprovider

import org.codehaus.groovy.grails.web.errors.GrailsExceptionResolver
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator
import org.springframework.web.servlet.ModelAndView
import org.springframework.web.servlet.view.json.MappingJacksonJsonView

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author Peter Schneider-Manzell
 */
class ExtendedGrailsExceptionResolver extends GrailsExceptionResolver {

    WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator()

    @Override
    ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        logger.error("Entering resolveException with ex "+ex.getClass()+" " +ex)
        if(ex instanceof  ClientRegistrationException){
            logger.info("Handling error: " + ex.getClass().getSimpleName() + ", " + ex.getMessage());
            ResponseEntity<OAuth2Exception> re =  exceptionTranslator.translate(new BadClientCredentialsException());
            return convertToJacksonView(response,re)
        }
        if(ex instanceof  OAuth2Exception){
            logger.info("Handling error: " + ex.getClass().getSimpleName() + ", " + ex.getMessage());
            ResponseEntity<OAuth2Exception> re =  exceptionTranslator.translate(ex);
            return convertToJacksonView(response,re)
        }
        return super.resolveException(request, response, handler, ex)
    }

    ModelAndView convertToJacksonView(HttpServletResponse response,ResponseEntity<OAuth2Exception> responseEntity) {
        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);
        outputMessage.setStatusCode(((ResponseEntity) responseEntity).getStatusCode());
        response.setStatus(responseEntity.getStatusCode().value())
        HttpHeaders entityHeaders = responseEntity.getHeaders();
        if (!entityHeaders.isEmpty()) {
            outputMessage.getHeaders().putAll(entityHeaders);
        }
        outputMessage.getBody()
        ModelAndView mav = new ModelAndView()
         MappingJacksonJsonView jacksonJsonView = new MappingJacksonJsonView()
        jacksonJsonView.setExtractValueFromSingleKeyModel(true);
        mav.setView(jacksonJsonView);
        mav.addObject(responseEntity.getBody())

        return mav;
    }
}
