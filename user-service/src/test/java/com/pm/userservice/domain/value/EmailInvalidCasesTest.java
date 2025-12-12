package com.pm.userservice.domain.value;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailInvalidCasesTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "no-at-symbol",
            "a@b",                 // no dot in domain
            "a@b.",                // trailing dot
            ".alice@example.com",  // local starts with dot
            "alice.@example.com",  // local ends with dot
            "al..ice@example.com", // consecutive dots in local
            "alice@exa..mple.com", // empty domain label
            "ali ce@example.com",  // space
            "alice@ example.com",
            "alice@exam_ple.com",  // underscore in domain label
            "alice@-example.com",  // domain label starts with hyphen
            "alice@example-.com",  // domain label ends with hyphen
            "alice@example.c",     // TLD too short (if your rule requires >=2)
            "alice@127.0.0.1",     // IP literal (reject unless you support it)
            "alice@[127.0.0.1]"    // bracketed IP (reject unless supported)
    })
    void rejects_bad_shapes(String raw) {
        assertThatThrownBy(() -> Email.of(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid email");
    }
}

