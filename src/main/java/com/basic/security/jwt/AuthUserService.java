package com.basic.security.jwt;

import com.basic.security.jwt.AuthUser;
import com.basic.security.repository.AuthUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

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
