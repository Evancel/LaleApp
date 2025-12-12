package com.pm.userservice.domain.value;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EmailNormalizationTest {

    @Test
    void trims_and_lowercases_domain_and_local() {
        Email e = Email.of("  Alice+tag@Example.COM ");
        assertThat(e.canonical()).isEqualTo("alice+tag@example.com"); // choose policy: local lowercased
    }

    @Test
    void equals_ignores_case_differences() {
        assertThat(Email.of("ALICE@EXAMPLE.com"))
                .isEqualTo(Email.of("alice@example.COM"));
    }

    @Test
    void preserves_plus_tag_in_canonical_by_default() {
        // Do NOT strip provider-specific tags unless your domain rules say so.
        assertThat(Email.of("me+news@example.com").canonical())
                .isEqualTo("me+news@example.com");
    }
}

