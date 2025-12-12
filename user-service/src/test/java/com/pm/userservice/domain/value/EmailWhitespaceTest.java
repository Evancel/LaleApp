package com.pm.userservice.domain.value;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailWhitespaceTest {

    @Test
    void trims_but_rejects_internal_whitespace() {
        assertThatThrownBy(() -> Email.of(" alice @example.com "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_control_chars() {
        String raw = "a\u0007@example.com"; // bell character
        assertThatThrownBy(() -> Email.of(raw))
                .isInstanceOf(IllegalArgumentException.class);
    }
}

