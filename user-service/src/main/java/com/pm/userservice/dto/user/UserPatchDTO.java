package com.pm.userservice.dto.user;

import java.util.Optional;

public record UserPatchDTO(
        Optional<String> name
) {}

