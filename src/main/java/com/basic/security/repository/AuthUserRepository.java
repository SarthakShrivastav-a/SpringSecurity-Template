package com.basic.security.repository;

import com.basic.security.jwt.AuthUser;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface AuthUserRepository extends MongoRepository<AuthUser,String> {
    Optional<AuthUser> findByEmail(String email);
}
