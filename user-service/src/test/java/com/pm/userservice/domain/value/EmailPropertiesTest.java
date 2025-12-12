package com.pm.userservice.domain.value;

import net.jqwik.api.*;
import org.apache.commons.validator.routines.EmailValidator;

import static org.assertj.core.api.Assertions.*;

class EmailPropertiesTest {

    @Provide
    Arbitrary<String> localParts() {
        // Simplified generator: letters, digits, . _ + -
        return Arbitraries.strings()
                .withChars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-")
                .ofMinLength(1).ofMaxLength(32)
                .filter(s -> !s.startsWith(".") && !s.endsWith(".") && !s.contains(".."));
    }

    @Provide
    Arbitrary<String> domainLabels() {
        return Arbitraries.strings()
                .withChars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
                .ofMinLength(2).ofMaxLength(20)
                .filter(s -> !s.startsWith("-") && !s.endsWith("-"));
    }

    @Provide
    Arbitrary<String> domains() {
        return Combinators.combine(domainLabels(), domainLabels())
                .as((a, b) -> a + "." + b);
    }

    @Provide
    Arbitrary<Email> validEmails() {
        var validator = EmailValidator.getInstance();

        return Combinators.combine(localParts(), domains())
                .as((local, domain) -> local + "@" + domain)
                .filter(validator::isValid)  // only keep what Apache accepts
                .map(Email::of);             // now safe: always valid
    }

    @Property(tries = 200)
    void canonical_has_lowercase_domain(@ForAll("validEmails") Email e) {
        String[] parts = e.canonical().split("@", 2);

        assertThat(parts[1]).isLowerCase();
        assertThat(e).isEqualTo(Email.of(parts[0] + "@" + parts[1]));
    }
}
