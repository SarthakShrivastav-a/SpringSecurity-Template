package com.basic.security.config;

import com.basic.security.jwt.AuthTokenFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Configuration class for setting up Spring Security in the application.
 *
 * This class defines beans and methods responsible for configuring authentication,
 * password encoding, and security filter chains. It ensures the integration of
 * JWT-based authentication with Spring Security's mechanisms, enforces stateless
 * session management, and secures API endpoints.
 *
 * Responsibilities:
 * - Configures an `AuthenticationManager` bean for processing and managing authentication.
 * - Provides a `PasswordEncoder` bean for secure password hashing and verification.
 * - Configures the application's security filter chain to define access policies,
 *   integrate the `AuthTokenFilter`, and enforce a stateless security context.
 *
 * Beans:
 * - `PasswordEncoder`: Defines a bean for `BCryptPasswordEncoder` to hash passwords.
 * - `AuthenticationManager`: Creates an authentication manager using the provided
 *   `AuthenticationConfiguration`.
 * - `SecurityFilterChain`: Configures security rules via `HttpSecurity` to enable
 *   JWT-based authentication and restrict access to secure endpoints.
 *
 * Security Configuration:
 * - Disables CSRF protection to align with stateless authentication.
 * - Permits access to predefined endpoints while requiring authentication for
 *   all other requests.
 * - Adds the `AuthTokenFilter` to the filter chain before the default
 *   `UsernamePasswordAuthenticationFilter`, allowing JWT validation for incoming requests.
 *
 * Logging:
 * - Provides detailed logging for key stages of security configuration and runtime behaviors.
 * - Logs the creation of security-related beans and processing of the security filter chain.
 *
 * This configuration is essential for securing REST APIs, managing authentication,
 * and enforcing authorization in a stateless architecture.
 */
@Configuration
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private AuthTokenFilter authTokenFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        logger.debug("AuthenticationManager bean created.");
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.debug("Configuring HttpSecurity.");
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests
//                        .requestMatchers("/api/customers/create").permitAll()
                        .requestMatchers(new AntPathRequestMatcher("")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("**/error/**")).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        logger.info("Security filter chain configuration complete.");
        return http.build();
    }
}
