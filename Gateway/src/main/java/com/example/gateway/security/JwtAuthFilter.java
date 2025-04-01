package com.example.gateway.security;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    // Define URL Patterns
    private static final String[] PUBLIC_URLS = {
            "/ms-auth/v3/api-docs/**", "/ms-auth/swagger-ui/**", "/ms-auth/swagger-ui.html",
            "/ms-auth/api/auth/register/**", "/ms-auth/api/auth/login/**",
            "/ms-auth/api/auth/verify-email/**", "/ms-auth/api/auth/resend-code/**",
            "/ms-auth/api/auth/registerAdmin/**", "/ms-auth/api/auth/refresh-token/**"
    };

    private static final String[] USER_URLS = { "/ms-auth/user/**" };
    private static final String[] ADMIN_URLS = { "/ms-auth/admin/**" };
    private static final String[] AUTHENTICATED_URLS = { "/ms-auth/secured/**" };


    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        System.out.println("Incoming request: {} {}" + path);
        System.out.println("Headers: {}"+ request.getHeaders());
        // Allow Public Endpoints Without Authentication
        if (isPathMatching(path, PUBLIC_URLS)) {
            System.out.println("Public endpoint accessed: {}"+ path);
            return chain.filter(exchange);
        }

        // Extract JWT from Authorization Header
        List<String> authHeaders = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeaders.get(0).substring(7); // Remove "Bearer " prefix

        try {
            if (!jwtUtil.isTokenValid(token)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String role = jwtUtil.extractRole(token);

            // Restrict Access Based on Role
            if (isPathMatching(path, ADMIN_URLS) && !"ADMIN".equals(role)) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
            if (isPathMatching(path, USER_URLS) && !"USER".equals(role)) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
            if (isPathMatching(path, AUTHENTICATED_URLS) && (!"USER".equals(role) && !"ADMIN".equals(role))) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            // Continue if the request is valid
            return chain.filter(exchange);

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    // Helper function to check if the path matches any pattern
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private boolean isPathMatching(String path, String[] patterns) {
        for (String pattern : patterns) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }
}
