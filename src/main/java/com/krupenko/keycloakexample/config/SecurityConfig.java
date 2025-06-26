package com.krupenko.keycloakexample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String ROLE_MANAGER = "MANAGER";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/manager.html").hasRole(ROLE_MANAGER)
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer((oauth2) -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
            return concatAuthorities(jwt, authorities);
        });
        return jwtAuthenticationConverter;
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oAuth2UserService() {
        var oidcUserService = new OidcUserService();
        return userRequest -> {
            var oidcUser = oidcUserService.loadUser(userRequest);
            var authorities = concatAuthorities(oidcUser, oidcUser.getAuthorities());
            return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }

    private List<GrantedAuthority> concatAuthorities(ClaimAccessor claimAccessor,
                                                     Collection<? extends GrantedAuthority> existedAuthorities) {
        List<String> roles = getRoles(claimAccessor);
        return Stream.concat(existedAuthorities.stream(),
                        roles.stream()
                                .filter(role -> role.startsWith(ROLE_PREFIX))
                                .map(SimpleGrantedAuthority::new)
                                .map(GrantedAuthority.class::cast))
                .toList();
    }

    private List<String> getRoles(ClaimAccessor claimAccessor) {
        var realmAccess = claimAccessor.getClaimAsMap("realm_access");
        return realmAccess != null
                ? (List<String>) realmAccess.get("roles")
                : List.of();
    }

}