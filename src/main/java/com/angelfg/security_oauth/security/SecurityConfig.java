package com.angelfg.security_oauth.security;

import com.angelfg.security_oauth.services.CustomerUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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

    // Provee la autenticacion
    @Bean
    public AuthenticationProvider authenticationProvider(PasswordEncoder encoder, CustomerUserDetailsService userDetails) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(encoder);
        authProvider.setUserDetailsService(userDetails);

        return authProvider;
    }

    // Configura el authorizationServer de autorizacion
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    // Configuracion de JWT en roles
    @Bean
    public JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthorityPrefix("");
        return converter;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(JwtGrantedAuthoritiesConverter settings) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(settings);
        return converter;
    }

    // Llaves RSA publica y privada
    private static KeyPair generateRSA() {
        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(RSA_SIZE);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        return keyPair;
    }

    // Obtener la llave publica y privada
    private static RSAKey generateKeys() {
        KeyPair keyPair = generateRSA();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    }

    // JWK => Json Web Key
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsa = generateKeys();
        JWKSet jwkSet = new JWKSet(rsa);

        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    // Decodifica el jwk generado por las lla publica y privada
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // Integrar los claims en el JWT
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            Authentication authentication = context.getPrincipal();

            Set<String> authorities =  authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                context.getClaims().claims(claim ->
                    claim.putAll(
                        Map.of(
                            "roles", authorities,
                            "owner", APPLICATION_OWNER,
                            "date_request", LocalDateTime.now().toString()
                        )
                    )
                );
            }

        };
    }

}
