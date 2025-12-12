package com.pm.userservice.domain.value;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailLengthTest {

    @Test
    void rejects_local_part_over_64_chars() {
        String local = "a".repeat(65);
        assertThatThrownBy(() -> Email.of(local + "@example.com"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_total_length_over_254() {
        String label = "a".repeat(63);
        String domain = label + "." + label + "." + label + "." + label + ".com"; // long but valid labels
        String local = "user";
        String email = local + "@" + domain;
        assertThat(email.length()).isGreaterThan(254);
        assertThatThrownBy(() -> Email.of(email))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void accepts_max_label_length_63() {
        String label63 = "a".repeat(63);
        Email e = Email.of("u@" + label63 + ".com");
        assertThat(e.canonical()).endsWith(".com");
    }
}

