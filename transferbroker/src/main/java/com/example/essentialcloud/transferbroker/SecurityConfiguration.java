package com.example.essentialcloud.transferbroker;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                .addFilterBefore(new AddAuthorityFilter(), AuthorizationFilter.class);
    return http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

//
//    private static final String REALM_ACCESS_CLAIM = "realm_access";
//    private static final String ROLES_CLAIM = "roles";
//    @Bean
//    @SuppressWarnings("unchecked")
//    public GrantedAuthoritiesMapper userAuthoritiesMapperForKeycloak() {
//        return authorities -> {
//            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
//            var authority = authorities.iterator().next();
//            boolean isOidc = authority instanceof OidcUserAuthority;
//
//            if (isOidc) {
//                var oidcUserAuthority = (OidcUserAuthority) authority;
//                var userInfo = oidcUserAuthority.getUserInfo();
//
//                if (userInfo.hasClaim(REALM_ACCESS_CLAIM)) {
//                    var realmAccess = userInfo.getClaimAsMap(REALM_ACCESS_CLAIM);
//                    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);
//                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
//                }
//            } else {
//                var oauth2UserAuthority = (OAuth2UserAuthority) authority;
//                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
//
//                if (userAttributes.containsKey(REALM_ACCESS_CLAIM)) {
//                    var realmAccess = (Map<String, Object>) userAttributes.get(REALM_ACCESS_CLAIM);
//                    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);
//                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
//                }
//            }
//            return mappedAuthorities;
//        };
//    }
//    Collection<GrantedAuthority> generateAuthoritiesFromClaim(Collection<String> roles) {
//        return roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
//    }
}
