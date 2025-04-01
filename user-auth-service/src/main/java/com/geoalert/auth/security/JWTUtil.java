package com.geoalert.auth.security;

import com.geoalert.auth.utils.AppConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

//@Service
//public class JWTUtil {
//
//    private String SECRET_KEY = "TaK+HaV^uvCHEFsEVfypW#7g9^k*Z8$V";
//
//    private SecretKey getSigningKey() {
//        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
//    }
//
//    public String extractUsername(String token) {
//        Claims claims = extractAllClaims(token);
//        return claims.getSubject();
//    }
//
//    public Date extractExpiration(String token) {
//        return extractAllClaims(token).getExpiration();
//    }
//
//    private Claims extractAllClaims(String token) {
//        return Jwts.parser()
//                .verifyWith(getSigningKey())
//                .build()
//                .parseSignedClaims(token)
//                .getPayload();
//    }
//
//    private Boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    public String generateToken(String username) {
//        Map<String, Object> claims = new HashMap<>();
//        return createToken(claims, username);
//    }
//
//    private String createToken(Map<String, Object> claims, String subject) {
//        return Jwts.builder()
//                .claims(claims)
//                .subject(subject)
//                .header().empty().add("typ","JWT")
//                .and()
//                .issuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 50)) // 5 minutes expiration time
//                .signWith(getSigningKey())
//                .compact();
//    }
//
//    public Boolean validateToken(String token) {
//        return !isTokenExpired(token);
//    }
//}


// for the correct response when expired token
//@Service
//public class JWTUtil {
//
//    private final String SECRET_KEY = "TaK+HaV^uvCHEFsEVfypW#7g9^k*Z8$V";
//    private final String REFRESH_SECRET_KEY = "GgEo6aLrT!r3fr3sh#K3y_Sup3r_S3cr3t";
//
//    private SecretKey getSigningKey(String key) {
//        return Keys.hmacShaKeyFor(key.getBytes());
//    }
//
//    public String extractUsername(String token, boolean isRefreshToken) {
//        String key = isRefreshToken ? REFRESH_SECRET_KEY : SECRET_KEY;
//        return extractAllClaims(token, key).getSubject();
//    }
//
//    public Date extractExpiration(String token) {
//        return extractAllClaims(token, SECRET_KEY).getExpiration();
//    }
//
//    private Claims extractAllClaims(String token, String key) {
//        return Jwts.parser()
//                .verifyWith(getSigningKey(key))
//                .build()
//                .parseSignedClaims(token)
//                .getPayload();
//    }
//
//    private Boolean isTokenExpired(String token, String key) {
//        return extractAllClaims(token, key).getExpiration().before(new Date());
//    }
//
//    public String generateToken(String username) {
//        return createToken(username, SECRET_KEY, 1000 * 60 * 1); // 1 minutes expiration
//    }
//
//    public String generateRefreshToken(String username) {
//        return createToken(username, REFRESH_SECRET_KEY, 1000 * 60 * 3); // 3 days expiration
//    }
//
//    private String createToken(String subject, String key, long expirationTime) {
//        return Jwts.builder()
//                .subject(subject)
//                .issuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + expirationTime))
//                .signWith(getSigningKey(key))
//                .compact();
//    }
//
//    public Boolean validateToken(String token) {
//        return !isTokenExpired(token, SECRET_KEY);
//    }
//
//    public Boolean validateRefreshToken(String token) {
//        return !isTokenExpired(token, REFRESH_SECRET_KEY);
//    }
//}


import io.jsonwebtoken.ExpiredJwtException;

@Service
public class JWTUtil {

    private final String SECRET_KEY = "TaK+HaV^uvCHEFsEVfypW#7g9^k*Z8$V";
    private final String REFRESH_SECRET_KEY = "GgEo6aLrT!r3fr3sh#K3y_Sup3r_S3cr3t";

    private SecretKey getSigningKey(String key) {
        return Keys.hmacShaKeyFor(key.getBytes());
    }

    public String extractEmail(String token, boolean isRefreshToken) {
        try {
            String key = isRefreshToken ? REFRESH_SECRET_KEY : SECRET_KEY;
            return extractAllClaims(token, key).getSubject();
        } catch (ExpiredJwtException e) {
            throw new ExpiredTokenException("Token has expired", e);
        }
    }


    private Claims extractAllClaims(String token, String key) {
        return Jwts.parser()
                .verifyWith(getSigningKey(key))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(String email) {
        return createToken(email, SECRET_KEY, 1000 * 60 * AppConstants.ACCESS_TOKEN_VALIDITY_MINUTES);
    }

    public String generateRefreshToken(String email) {
        return createToken(email, REFRESH_SECRET_KEY, 1000 * 60 * AppConstants.REFRESH_TOKEN_VALIDITY_MINUTES);
    }

    private String createToken(String subject, String key, long expirationTime) {
        return Jwts.builder()
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(key))
                .compact();
    }

        private Boolean isTokenExpired(String token, String key) {
        try{
            return extractAllClaims(token, key).getExpiration().before(new Date());
        }
        catch (ExpiredJwtException e){
            return true;
        }
    }
        public Boolean validateToken(String token) {
        return !isTokenExpired(token, SECRET_KEY);
    }

    public Boolean validateRefreshToken(String token) {
        return !isTokenExpired(token, REFRESH_SECRET_KEY);
    }


}


