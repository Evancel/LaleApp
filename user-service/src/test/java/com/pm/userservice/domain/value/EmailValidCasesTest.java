package com.pm.userservice.domain.value;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class EmailValidCasesTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "a@b.co",
            "user.name+tag@sub-domain.example.com",
            "u_n-d.e.r@exa-mple.io",
            "customer/department=shipping@example.com", // allowed specials in local, if you support them
            "\"quoted local\"@example.org"              // quoted local, if supported
    })
    void accepts_shapes_we_support(String raw) {
        Email e = Email.of(raw);
        // domain must be lowercased in canonical
        String domain = e.canonical().substring(e.canonical().indexOf('@') + 1);
        assertThat(domain).isLowerCase();
    }
}

