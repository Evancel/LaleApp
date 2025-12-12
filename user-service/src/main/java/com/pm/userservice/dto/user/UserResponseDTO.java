package com.pm.userservice.dto.user;

import java.util.List;
import java.util.UUID;

public class UserResponseDTO {
    private UUID id;
    private String email;
    private List<String> roles;

    public UserResponseDTO(){}

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
