package com.learn.auth.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component
public class CustomConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final Logger logger = LoggerFactory.getLogger(CustomConverter.class);

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        if (jwt == null) {
            logger.warn("JWT is null");
            return List.of();
        }
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // Process realm roles
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.get("roles") != null) {
            ((List<String>) realmAccess.get("roles")).stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .forEach(authorities::add);
        }
        // Process resource roles (client-specific)
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            resourceAccess.forEach((clientName, clientRoles) -> {
                if (clientRoles instanceof Map) {
                    Object roles = ((Map<?, ?>) clientRoles).get("roles");
                    if (roles instanceof List) {
                        ((List<String>) roles).stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + clientName + "_" + role))
                                .forEach(authorities::add);
                    }
                }
            });
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Extracted authorities from JWT: {}", authorities);
        }

        return authorities;
    }
}