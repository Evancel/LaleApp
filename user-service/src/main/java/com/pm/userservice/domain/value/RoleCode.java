package com.pm.userservice.domain.value;

import java.util.Locale;
import java.util.Objects;

public final class RoleCode {
    private final String code; // canonical UPPER

    private RoleCode(String code) { this.code = code; }

    public static RoleCode of(String input) {
        if (input == null || input.isBlank()) throw new IllegalArgumentException("role is required");
        return new RoleCode(input.trim().toUpperCase(Locale.ROOT));
    }

    public String canonical() { return code; }
    @Override public String toString() { return code; }
    @Override public boolean equals(Object o){ return o instanceof RoleCode rc && rc.code.equals(code);}
    @Override public int hashCode(){ return Objects.hash(code);}
}

