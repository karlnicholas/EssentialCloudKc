package com.example.essentialcloud.transferbroker;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Slf4j
class AddAuthorityFilter implements Filter {
    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";
    @Override
    @SuppressWarnings("unchecked")
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            try {
                Jwt token = (Jwt) authentication.getPrincipal();
                Map<String, Object> claims = token.getClaims();
                if (claims.containsKey(REALM_ACCESS_CLAIM)) {
                    Map<String, List<String>> realmAccess = (Map<String, List<String>>)claims.get(REALM_ACCESS_CLAIM);
                    if (realmAccess.containsKey(ROLES_CLAIM)) {
                        if (realmAccess.get(ROLES_CLAIM).contains("TRANSFER_ADMIN") ) {
                            System.out.println(token);
                            Collection<? extends GrantedAuthority> oldAuthorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
                            List<GrantedAuthority> updatedAuthorities = new ArrayList<>();
                            SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_TRANSFER_ADMIN");
                            updatedAuthorities.add(authority);
                            updatedAuthorities.addAll(oldAuthorities);

                            SecurityContextHolder.getContext().setAuthentication(
                                    new UsernamePasswordAuthenticationToken(
                                            SecurityContextHolder.getContext().getAuthentication().getPrincipal(),
                                            SecurityContextHolder.getContext().getAuthentication().getCredentials(),
                                            updatedAuthorities)
                            );
                        }
                    }
                }
            } catch (Exception ex) {
                log.error("Error finding user info {}", ((Jwt)authentication.getPrincipal()).getClaims().get("sub").toString());
            }
        }
        filterChain.doFilter(request, response);
    }

}
