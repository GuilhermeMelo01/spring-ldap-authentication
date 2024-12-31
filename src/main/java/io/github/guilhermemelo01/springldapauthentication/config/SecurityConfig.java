package io.github.guilhermemelo01.springldapauthentication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private String LDAP_URL = System.getenv("LDAP_URL");
    private String ADMIN_USER_DN = System.getenv("ADMIN_USER_DN");
    private String ADMIN_USER_PASSWORD = System.getenv("ADMIN_USER_PASSWORD");

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().fullyAuthenticated()
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // LDAP TEMPLATE
    @Bean
    public LdapTemplate ldapTemplate(){
        return new LdapTemplate(contextSource());
    }

    // LDAP CONTEXT AUTHENTICATION
    @Bean
    public LdapContextSource contextSource(){
        LdapContextSource ldapContextSource = new LdapContextSource();
        ldapContextSource.setUrl(LDAP_URL);
        ldapContextSource.setUserDn(ADMIN_USER_DN);
        ldapContextSource.setPassword(ADMIN_USER_PASSWORD);

        return ldapContextSource;
    }

    // AUTHENTICATION MANAGER
    @Bean
    AuthenticationManager authManager(BaseLdapPathContextSource source){
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(source);
        factory.setUserDnPatterns("cn={0},ou=users,ou=system");
        return factory.createAuthenticationManager();
    }
}
