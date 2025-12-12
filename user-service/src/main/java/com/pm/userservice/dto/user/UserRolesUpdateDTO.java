package com.pm.userservice.dto.user;

import java.util.Collection;

public record UserRolesUpdateDTO(
        Collection<String> roles
) {}
