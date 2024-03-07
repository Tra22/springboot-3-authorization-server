package com.tra21.authorization_server.config.security;

import com.tra21.authorization_server.models.User;
import com.tra21.authorization_server.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Configuration
@DependsOn(value = {SecurityConfig.BEAN_ID,
        AuthenticationProviderConfigurer.BEAN_ID})
@Slf4j(topic = "CONFIGURER")
@RequiredArgsConstructor
public class BootstrapDataConfigurer {
    private final UserRepository userRepository;
    private final JdbcOperations jdbcOperations;
    private final PasswordEncoder passwordEncoder;
    @EventListener(value = ApplicationReadyEvent.class)
    @Transactional
    public void init() {
        initUser();
        initClient();
    }
    private void initUser(){
        User user = User.builder()
                .email("test@gmail.com")
                .username("test")
                .password(passwordEncoder.encode("test"))
                .enabled(true)
                .accExpired(false)
                .accLocked(false)
                .credsExpired(false)
                .build();
        Optional<User> userFetch = userRepository.findByEmail(user.getEmail());
        if(userFetch.isEmpty()){
            userRepository.save(user);
        }
    }
    private void initClient(){
        RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                                ClientAuthenticationMethod.NONE
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .redirectUri("http://127.0.0.1:9095/client/callback")
//                .redirectUri("http://127.0.0.1:9095/client/authorized")
//                .redirectUri("http://127.0.0.1:9095/client")
//                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .postLogoutRedirectUri("http://127.0.0.1:9001/logout")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access", "user"
                )))
                .clientSettings(
                        ClientSettings
                                .builder()
                                .requireProofKey(false)
                                .requireAuthorizationConsent(true)
                                .build()
                )
                .build();
        RegisteredClient demoClientPkce = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-pkce")
                .clientAuthenticationMethods(methods -> methods.add(
                        ClientAuthenticationMethod.NONE
                ))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-opaque")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientPkceOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-pkce-opaque")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethods(methods -> methods.add(
                        ClientAuthenticationMethod.NONE
                ))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();

        // Save registered client in db as if in-memory
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);
        if(registeredClientRepository.findByClientId(demoClient.getClientId()) == null)
            registeredClientRepository.save(demoClient);
        if(registeredClientRepository.findByClientId(demoClientPkce.getClientId()) == null)
            registeredClientRepository.save(demoClientPkce);
        if(registeredClientRepository.findByClientId(demoClientOpaque.getClientId()) == null)
            registeredClientRepository.save(demoClientOpaque);
        if(registeredClientRepository.findByClientId(demoClientPkceOpaque.getClientId()) == null)
            registeredClientRepository.save(demoClientPkceOpaque);
    }
}
