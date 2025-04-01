package com.geoalert.auth.security;


public class ExpiredTokenException extends RuntimeException {
    public ExpiredTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}

