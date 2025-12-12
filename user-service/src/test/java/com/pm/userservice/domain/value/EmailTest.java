package com.pm.userservice.domain.value;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

public class EmailTest {
    @Test
    void of_trims_and_lowercases_domain() {
        Email e = Email.of("  Alice@Example.COM ");
        assertThat(e.canonical()).isEqualTo("alice@example.com");
    }

    @Test
    void equals_based_on_canonical() {
        assertThat(Email.of("ALICE@EXAMPLE.com"))
                .isEqualTo(Email.of("alice@example.COM"));
    }

    @Test
    void of_rejects_invalid() {
        assertThatThrownBy(() -> Email.of("not-an-email"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid email");
    }

    @Test
    void of_rejects_tld_too_short() {
        assertThatThrownBy(() -> Email.of("AliCE.asdf@example.c"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid email");
    }
}
