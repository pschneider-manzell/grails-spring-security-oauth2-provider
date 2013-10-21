grails.servlet.version = "2.5" // Change depending on target container compliance (2.5 or 3.0)
grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"
grails.project.work.dir = "target/work"
grails.project.docs.output.dir = 'target/docs' // for backwards-compatibility, the docs are checked into gh-pages branch
grails.project.target.level = 1.7
grails.project.source.level = 1.7

grails.release.scm.enabled = false

grails.project.dependency.resolver = "maven"

grails.project.fork = [
        // configure settings for compilation JVM, note that if you alter the Groovy version forked compilation is required
        //  compile: [maxMemory: 256, minMemory: 64, debug: false, maxPerm: 256, daemon:true],

        // configure settings for the test-app JVM, uses the daemon by default
        test: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, daemon:true],
        // configure settings for the run-app JVM
        run: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
        // configure settings for the run-war JVM
        war: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
        // configure settings for the Console UI JVM
        console: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256]
]

// Code Narc
codenarc.reports = {
	XmlReport('xml') {
		outputFile = 'target/test-reports/CodeNarcReport.xml'
		title = 'OAuth2 Provider Plugin Report'
	}
	HtmlReport('html') {
		outputFile = 'target/test-reports/CodeNarcReport.html'
		title = 'OAuth2 Provider Plugin Report'
	}
}

grails.project.dependency.resolution = {
	inherits 'global'
	log 'warn'
	repositories {
		grailsPlugins()
		grailsHome()
		grailsCentral()

//		mavenLocal()
		mavenCentral()

        mavenRepo "http://repo.spring.io/milestone/"
	}

	dependencies {

//		compile('org.springframework.security:spring-security-crypto:3.1.4.RELEASE') {
//			excludes 'spring-core', 'commons-logging'
//		}
		compile 'org.springframework.security.oauth:spring-security-oauth2:1.0.5.RELEASE', {
            excludes 'aopalliance', 'commons-codec', 'commons-logging', 'fest-assert', 'groovy', 'hsqldb',
                    'jcl-over-slf4j', 'junit', 'logback-classic', 'mockito-core', 'powermock-api-mockito',
                    'powermock-api-support', 'powermock-core', 'powermock-module-junit4',
                    'powermock-module-junit4-common', 'powermock-reflect', 'spock-core', 'spring-aop',
                    'spring-beans', 'spring-context', 'spring-core', 'spring-expression', 'spring-jdbc',
                    'spring-security-core', 'spring-test', 'spring-tx', 'spring-web', 'spring-webmvc',
                    'tomcat-servlet-api'
		}
		compile 'org.springframework.security:spring-security-config:3.2.0.RC1', {
            excludes 'aopalliance', 'commons-codec', 'commons-logging', 'fest-assert', 'groovy', 'hsqldb',
                    'jcl-over-slf4j', 'junit', 'logback-classic', 'mockito-core', 'powermock-api-mockito',
                    'powermock-api-support', 'powermock-core', 'powermock-module-junit4',
                    'powermock-module-junit4-common', 'powermock-reflect', 'spock-core', 'spring-aop',
                    'spring-beans', 'spring-context', 'spring-core', 'spring-expression', 'spring-jdbc',
                    'spring-security-core', 'spring-test', 'spring-tx', 'spring-web', 'spring-webmvc',
                    'tomcat-servlet-api'
		}
	}
	
	plugins {
        // plugins for the build system only
        build (":tomcat:7.0.42") {
            export = false
        }

        // plugins needed at runtime but not for compilation
        runtime (":hibernate:3.6.10.2") {  // or ":hibernate4:4.1.11.2"
            export = false
        }
		// Release
		build (':release:2.2.1') {
			export = false
			excludes 'rest-client-builder'
		}
		build (':rest-client-builder:1.0.3') {
			export = false
		}

		// Testing
		test ':code-coverage:1.2.6', {
			export = false
		}
		test ':codenarc:0.15', {
			export = false
		}
		compile ':spring-security-core:2.0-RC2'
	}
}
