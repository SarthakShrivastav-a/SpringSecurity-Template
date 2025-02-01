package com.basic.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * The AuthTokenFilter class serves as a custom filter that intercepts HTTP requests
 * to validate and process JWT-based authentication.
 *
 * It extends the OncePerRequestFilter class to ensure execution only once per HTTP request.
 *
 * Responsibilities include:
 * - Parsing the JWT from the Authorization header of incoming HTTP requests
 * - Validating the JWT token using the JwtUtility component
 * - Extracting the username from the JWT and loading user details using the AuthUserService
 * - Setting up user authentication in the Spring Security context
 *
 * This filter is primarily used to authenticate users for protected endpoints
 * and attach the user’s authentication details to the security context of the application.
 *
 * Exceptions during JWT processing are logged, and the filter chain is unconditionally continued.
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtility jwtUtility;

    @Autowired
    private AuthUserService authUserService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        logger.debug("AuthTokenFilter triggered for URI: {}", requestUri);

        try {
            String jwt = parseJwt(request);

            if (jwt != null && jwtUtility.validateJwtToken(jwt)) {
                String username = jwtUtility.getUserNameFromJwtToken(jwt);
                logger.debug("Valid JWT found for user: {}", username);

                UserDetails userDetails = authUserService.loadUserByUsername(username);

                if (userDetails != null) {
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities()
                            );

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    logger.info("User {} successfully authenticated with JWT.", username);
                }
            } else {
                logger.warn("No valid JWT found for request: {}", requestUri);
            }
        } catch (Exception e) {
            logger.error("Authentication processing error: {}", e.getMessage(), e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtility.getJwtFromHeader(request);
        logger.debug("Extracted JWT from request: {}", jwt);
        return jwt;
    }
}
