package com.angelfg.security_oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityConfig {

    private static final String[] USER_RESOURCES = {"/loans/**", "/balance/**"};
    private static final String[] ADMIN_RESOURCES = {"/accounts/**", "/cards/**"};
    private static final String AUTH_WRITE = "write";
    private static final String AUTH_READ = "read";
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_USER = "USER";
    private static final String LOGIN_RESOURCE = "/login";
    private static final String RSA = "RSA";
    private static final Integer RSA_SIZE = 2048;
    private static final String APPLICATION_OWNER = "Angelfgdeveloper";

    // Es el cliente estatico - ejemplo
//    @Bean
//    public RegisteredClientRepository clientRepository() {
//        RegisteredClient client = RegisteredClient
//            .withId(UUID.randomUUID().toString())
//            .clientId("angelfgdeveloper")
//            .clientSecret("secret")
//            .scope("read")
//            .redirectUri("http://localhost:8080")
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // user and password
//            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//            .build();
//
//        return new InMemoryRegisteredClientRepository(client);
//    }

    // Configuracion del Authorization Server
    @Bean
    @Order(1) // orden de carga de los beans
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http); // configuracion default

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_RESOURCE)));

        return http.build();
    }

    // Configuracion para el cliente
    @Bean
    @Order(2)
    public SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(Customizer.withDefaults());

        http.authorizeHttpRequests(auth -> auth
            // Privilegios
            .requestMatchers(ADMIN_RESOURCES).hasAuthority(AUTH_WRITE)
            .requestMatchers(USER_RESOURCES).hasAuthority(AUTH_READ)

//            Roles
//            .requestMatchers(ADMIN_RESOURCES).hasRole(ROLE_ADMIN)
//            .requestMatchers(USER_RESOURCES).hasRole(ROLE_USER)
            .anyRequest().permitAll()
        );

        // El oauth va a estar configurado con jwt
        http.oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));

        return http.build();
    }

    // Configuracion para el usuario
    @Bean
    @Order(3)
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity http) throws Exception {

        // Roles
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers(ADMIN_RESOURCES).hasRole(ROLE_ADMIN)
            .requestMatchers(USER_RESOURCES).hasRole(ROLE_USER)
            .anyRequest().permitAll()
        );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
