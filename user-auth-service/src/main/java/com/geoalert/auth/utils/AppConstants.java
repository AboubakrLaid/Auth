package com.geoalert.auth.utils;

public class AppConstants {
    public static final String[] PUBLIC_URLS = { "/v3/api-docs/**", "/swagger-ui/**", "/api/auth/register/**", "/api/auth/login/**", "/api/auth/verify-email/**", "/api/auth/resend-code/**","/api/auth/registerAdmin/**", "/api/auth/refresh-token/**" };
    public static final long ACCESS_TOKEN_VALIDITY_MINUTES = 1;
    public static final long REFRESH_TOKEN_VALIDITY_MINUTES = 1;
}
