package com.pm.userservice.dto.auth;

import com.pm.userservice.dto.user.UserResponseDTO;

public class LoginResponseDTO {
    private String token;
    private UserResponseDTO user;

    public LoginResponseDTO(String token, UserResponseDTO user) {
        this.token = token;
        this.user = user;
    }

    public String getToken() {
        return token;
    }

    public UserResponseDTO getUser() {
        return user;
    }
}

