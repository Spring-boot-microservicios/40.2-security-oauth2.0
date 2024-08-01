package com.angelfg.security_oauth.security;

import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

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

}
