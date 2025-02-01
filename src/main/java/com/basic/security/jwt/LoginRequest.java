package com.basic.security.jwt;

/**
 * Represents a request containing login credentials for user authentication.
 *
 * The LoginRequest class captures the information submitted by a user during
 * an authentication process, typically including their email and password.
 * This data is used to verify the user's identity and initiate a session.
 *
 * Fields:
 * - `email`: The user's email address, which uniquely identifies the user.
 * - `password`: The user's password, used alongside the email for verification.
 *
 * Getters and Setters:
 * This class provides getter and setter methods to access and modify
 * the email and password fields.
 *
 * Use Cases:
 * - Primarily used as a data transfer object (DTO) in authentication scenarios.
 * - Often utilized with controllers to handle user login requests.
 *
 * Thread Safety:
 * Instances of this class are not thread-safe as it is designed for use in
 * single-threaded request processing.
 */
public class LoginRequest {
    private String email;

    private String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

