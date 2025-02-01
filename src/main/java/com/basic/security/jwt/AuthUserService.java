package com.basic.security.jwt;

import com.basic.security.jwt.AuthUser;
import com.basic.security.repository.AuthUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Service class responsible for loading user details during authentication.
 *
 * This class implements the Spring Security interface UserDetailsService to
 * provide user-specific data required for authentication and authorization processes.
 * The user data is sourced from the {@code AuthUserRepository}, which interacts with
 * the underlying data store to fetch user details based on email.
 *
 * Responsibilities:
 * - Locate the user by their email address.
 * - Retrieve the user's hashed password and role from the database.
 * - Construct a Spring Security {@code UserDetails} object with the loaded details.
 *
 * The {@code loadUserByUsername} method throws a {@code UsernameNotFoundException}
 * if no user is found associated with the provided email.
 *
 * This class integrates with Spring's dependency injection mechanism and is annotated
 * as a service component with {@code @Service}.
 *
 * Dependencies:
 * - {@code AuthUserRepository}: Repository interface for accessing stored user data.
 *
 * Exceptions:
 * - {@code UsernameNotFoundException}: Thrown if the user with the specified email is not found.
 *
 * Security:
 * The returned {@code UserDetails} instance includes granted authorities derived from
 * the user's role, enabling role-based access control mechanisms in the application.
 */
@Service
public class AuthUserService implements UserDetailsService {

    @Autowired
    private AuthUserRepository authUserRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AuthUser user = authUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not Found "+ email));
        return User.withUsername(user.getEmail())
                .password(user.getHashedPassword())
                .roles(user.getRole())
                .build();
        //this can also be written as
        /*
        * return new User(
        *                   authUser.getEmail(),
        *                   authUser.getHashedPassword(),
        * */
    }
}
