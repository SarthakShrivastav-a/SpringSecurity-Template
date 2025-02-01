package com.basic.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The JwtUtility class provides functionality to generate, parse, and validate
 * JSON Web Tokens (JWTs), as well as extract claims like username and roles.
 *
 * This class is designed to handle JWT-related operations within the application,
 * enabling secure stateless authentication and authorization.
 *
 * Key responsibilities include:
 * - Generating JWTs with specified claims such as roles and username.
 * - Parsing JWTs to extract claims, including username and roles.
 * - Validating the authenticity and expiration of JWTs.
 * - Extracting JWTs from HTTP request headers.
 *
 * Dependencies:
 * - `javax.crypto.SecretKey` is utilized for signing and validating the token using HMAC-SHA.
 * - Signing and cryptographic operations are performed using `io.jsonwebtoken` library.
 *
 * Configuration:
 * The class relies on externalized configuration properties:
 * - `spring.app.jwtSecret`: A base64-encoded secret key for signing JWTs.
 * - `spring.app.jwtExpirationMs`: Duration in milliseconds for which the JWT is valid.
 *
 * Token Structure:
 * Tokens include claims for:
 * - Subject: The user's username.
 * - Roles: The user's authorities/roles.
 *
 * Exception Handling:
 * Handles exceptions such as invalid token format, unsupported token, expired token,
 * and empty claims string, logging relevant error messages for debugging purposes.
 */
@Component
public class JwtUtility {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtility.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload().getSubject();
    }

    public String getRoleFromJwtToken(String token) {
        List<String> roles = Jwts.parser()
                .verifyWith((SecretKey)key())
                .build()
                .parseSignedClaims(token)
                .getPayload().get("roles", List.class);

        return roles != null && !roles.isEmpty() ? roles.get(0) : null;
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().verifyWith((SecretKey)key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
