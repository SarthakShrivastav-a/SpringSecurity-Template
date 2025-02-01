package com.basic.security.jwt;


import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Document(collection = "AuthUser")
public class AuthUser {

    @Id
    private String id;

    private String email;

    @JsonIgnore
    private String hashedPassword;

    private String role;

    public AuthUser(String id,String email,String hashedPassword,String role){
        this.id = id;
        this.email = email;
        this.hashedPassword = hashedPassword;
        this.role = role;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    public void setHashedPassword(String hashedPassword) {
        this.hashedPassword = hashedPassword;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public GrantedAuthority getAuthority() {
        return new SimpleGrantedAuthority(role); //for role
    }
}
