package com.example.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.example.domain.SocialType.GOOGLE;
import static com.example.domain.SocialType.KAKAO;

@Configuration
public class OAuth2LoginConfig {
    private static final String DEFAULT_LOGIN_REDIRECT_URL = "http://localhost:8080/login/oauth2/code/kakao";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
/*
        List<ClientRegistration> registrations = properties.getRegistration().keySet().stream()
                .map(client -> getRegistration(properties, client))
                .filter(Objects::nonNull).collect(Collectors.toList());
*/


        return new InMemoryClientRegistrationRepository(this.googleClientRegistration(properties), this.kakaoClientRegistration(properties));
    }

    private ClientRegistration getRegistration(OAuth2ClientProperties properties, String socialType) {
        if (socialType.equals(GOOGLE.getValue())) {
            OAuth2ClientProperties.Registration registration
                    = properties.getRegistration().get(GOOGLE.getValue());
            return CommonOAuth2Provider.GOOGLE.getBuilder(socialType)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope("email", "profile")
                    .build();
        }else if(socialType.equals(KAKAO.getValue())){
            OAuth2ClientProperties.Registration registration
                    = properties.getRegistration().get(KAKAO.getValue());
            OAuth2ClientProperties.Provider provider = properties.getProvider().get(KAKAO.getValue());
            return ClientRegistration.withRegistrationId(socialType)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(DEFAULT_LOGIN_REDIRECT_URL)
                    .scope(registration.getScope())
                    .authorizationUri(provider.getAuthorizationUri())
                    .tokenUri(provider.getTokenUri())
                    .userInfoUri(provider.getUserInfoUri())
                    .userNameAttributeName(IdTokenClaimNames.SUB)
                    .clientName("Kakao")
                    .build();
        }
        return null;
    }



    private ClientRegistration googleClientRegistration(OAuth2ClientProperties properties) {
        return CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .build();
    }
    private ClientRegistration kakaoClientRegistration(OAuth2ClientProperties properties) {
        OAuth2ClientProperties.Registration registration
                = properties.getRegistration().get(KAKAO.getValue());
        OAuth2ClientProperties.Provider provider = properties.getProvider().get(KAKAO.getValue());
        return ClientRegistration.withRegistrationId(KAKAO.getValue())
                .clientId(registration.getClientId())
                .clientSecret(registration.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(DEFAULT_LOGIN_REDIRECT_URL)
                .scope(registration.getScope())
                .authorizationUri(provider.getAuthorizationUri())
                .tokenUri(provider.getTokenUri())
                .userInfoUri(provider.getUserInfoUri())
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName("Kakao")
                .build();
    }
}
