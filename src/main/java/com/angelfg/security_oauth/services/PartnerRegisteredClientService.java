package com.angelfg.security_oauth.services;

import com.angelfg.security_oauth.entities.PartnerEntity;
import com.angelfg.security_oauth.repositories.PartnerRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class PartnerRegisteredClientService implements RegisteredClientRepository {

    private final PartnerRepository partnerRepository;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
       return null;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<PartnerEntity> partnerOpt = this.partnerRepository.findByClientId(clientId);

        return partnerOpt.map(partner -> {

            // Obtiene: authorization_code,refresh_token
            List<AuthorizationGrantType> authorizationGrantTypes = Arrays.stream(partner.getGrantTypes().split(","))
                    .map(AuthorizationGrantType::new)
                    .toList();

            // Obtiene: client_secret_basic,client_secret_jwt
            List<ClientAuthenticationMethod> clientAuthenticationMethods = Arrays.stream(partner.getAuthenticationMethods().split(","))
                    .map(ClientAuthenticationMethod::new)
                    .toList();

            // Obtiene: read,write
            List<String> scopes = Arrays.stream(partner.getScopes().split(",")).toList();

            // Generamos el registro del client dinamico
            return RegisteredClient
                    .withId(partner.getId().toString())
                    .clientId(partner.getClientId())
                    .clientSecret(partner.getClientSecret())
                    .clientName(partner.getClientName())
                    .redirectUri(partner.getRedirectUri())
                    .postLogoutRedirectUri(partner.getRedirectUriLogout())
                    .clientAuthenticationMethod(clientAuthenticationMethods.get(0))
                    .clientAuthenticationMethod(clientAuthenticationMethods.get(1))
                    .scope(scopes.get(0))
                    .scope(scopes.get(1))
                    .authorizationGrantType(authorizationGrantTypes.get(0))
                    .authorizationGrantType(authorizationGrantTypes.get(1))
                    .tokenSettings(this.tokenSettings())
                    .build();

        }).orElseThrow(() -> new BadCredentialsException("Client not exist"));
    }

    // Tiempo de vida del token
    private TokenSettings tokenSettings() {
        return TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofHours(8))
            .build();
    }

}
