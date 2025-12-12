package com.pm.userservice.domain.value;

import org.apache.commons.validator.routines.EmailValidator;

import java.util.Locale;
import java.util.Objects;

public final class Email {
    private final String raw;        // what client sent (for messages)
    private final String canonical;  // what we persist & compare (unique index on LOWER(email))

    private Email(String raw, String canonical) {
        this.raw = raw;
        this.canonical = canonical;
    }

    public static Email of(String input) {
        if (input == null) throw new IllegalArgumentException("email is required");
        String trimmed = input.trim();
        if (trimmed.isEmpty() || !EmailValidator.getInstance().isValid(trimmed)) {
            throw new IllegalArgumentException("invalid email format");
        }
        // Split + normalize: lowercase, punycode domain, collapse dots/spaces around '@'
        int at = trimmed.lastIndexOf('@');
        String local = trimmed.substring(0, at);
        String domain = trimmed.substring(at + 1);

        // --- POLICY: reject domain literals like [127.0.0.1] or [IPv6:...]
        if (domain.startsWith("[") && domain.endsWith("]")) {
            throw new IllegalArgumentException("invalid email format"); // domain literal not allowed
        }

        // reject raw numeric hosts if you want:
         if (domain.chars().allMatch(ch -> ch == '.' || Character.isDigit(ch))) {
             throw new IllegalArgumentException("invalid email format");
         }

        // lowercase both parts for case-insensitive uniqueness
        String normDomain = domain.toLowerCase(Locale.ROOT);
        String normLocal = local.toLowerCase(Locale.ROOT);

        String canonical = normLocal + "@" + normDomain;
        return new Email(trimmed, canonical);
    }

    /**
     * Value used for persistence and uniqueness (e.g., unique index on LOWER(email)).
     */
    public String canonical() {
        return canonical;
    }

    /**
     * Original input (useful for messages/logs).
     */
    public String raw() {
        return raw;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Email other)) return false;
        return canonical.equals(other.canonical);
    }

    @Override
    public int hashCode() {
        return Objects.hash(canonical);
    }

    @Override
    public String toString() {
        return canonical;
    }
}

