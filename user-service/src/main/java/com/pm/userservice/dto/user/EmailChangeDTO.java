package com.pm.userservice.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record EmailChangeDTO(
        @NotBlank
        @Email
        String newEmail,
        @NotBlank
        String currentPassword
) {
}
