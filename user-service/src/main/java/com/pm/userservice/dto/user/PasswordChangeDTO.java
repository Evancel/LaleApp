package com.pm.userservice.dto.user;

import com.pm.userservice.validation.StrongPassword;
import jakarta.validation.constraints.NotBlank;

public record PasswordChangeDTO(
        @NotBlank
        String oldPassword,
        @NotBlank
        @StrongPassword
        String newPassword
) {}
