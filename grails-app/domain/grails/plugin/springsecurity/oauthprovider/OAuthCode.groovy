package grails.plugin.springsecurity.oauthprovider

class OAuthCode {

    String code
    byte[] authentication

    Date dateCreated

    static constraints = {
        code blank: false, nullable: false, unique: true
        authentication maxSize: 1024*5 // 5kb
    }

    static mapping = {
        version false
    }
}
