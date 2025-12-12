package com.pm.userservice.domain.value;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleCodeTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   ", "\t", "\n"})
    void of_throws_for_null_or_blank(String input) {
        assertThatThrownBy(() -> RoleCode.of(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("role is required");
    }

    @Test
    void of_trims_and_uppercases_input() {
        RoleCode rc = RoleCode.of("  admin  ");

        assertThat(rc.canonical()).isEqualTo("ADMIN");
        assertThat(rc.toString()).isEqualTo("ADMIN"); // same in your class
    }

    @Test
    void equals_and_hashCode_use_canonical_code() {
        RoleCode a = RoleCode.of("admin");
        RoleCode b = RoleCode.of(" ADMIN  ");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());

        Set<RoleCode> set = new HashSet<>();
        set.add(a);
        set.add(b);

        assertThat(set).hasSize(1);
    }
}
