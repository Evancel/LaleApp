package com.pm.userservice.dto.user;

import com.pm.userservice.validation.StrongPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class UserRequestDTO {
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be a valid email address")
    private String email;

    @NotBlank(message="Password is required")
    @StrongPassword
    private String password;

    private String role;

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

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
