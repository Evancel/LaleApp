package com.pm.userservice.repository;

import com.pm.userservice.domain.auth.Role;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.repository.auth.RoleRepository;
import com.pm.userservice.repository.user.UserProfileRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class UserProfileRepositoryTest {

    @Autowired
    private UserProfileRepository userRepo;

    @Autowired
    RoleRepository roleRepo;

    @Test
    void existsByEmail_returns_true_when_user_with_email_exists() {
        UserProfile user = new UserProfile();
        user.setEmail("alice@example.com");
        user.setPassword("secret");
        userRepo.save(user);

        boolean exists = userRepo.existsByEmail("alice@example.com");

        assertThat(exists).isTrue();
    }

    @Test
    void existsByEmail_returns_false_when_no_user_with_email() {
        boolean exists = userRepo.existsByEmail("bob@example.com");

        assertThat(exists).isFalse();
    }

    @Test
    void existsByEmailAndIdNot_ignores_same_user_and_detects_other() {
        UserProfile user1 = new UserProfile();
        user1.setEmail("alice@example.com");
        user1.setPassword("secret");
        user1 = userRepo.save(user1);

        UserProfile user2 = new UserProfile();
        user2.setEmail("bob@example.com");
        user2.setPassword("secret");
        user2 = userRepo.save(user2);

        // “Is there any other user with alice@example.com?”
        boolean existsForSameId = userRepo.existsByEmailAndIdNot("alice@example.com", user1.getId());
        boolean existsForOtherId = userRepo.existsByEmailAndIdNot("alice@example.com", user2.getId());

        assertThat(existsForSameId).isFalse();  // only this user has that email
        assertThat(existsForOtherId).isTrue();  // from perspective of user2, yes, someone else uses this email
    }

    @Test
    void findByEmail_returns_user_when_exists() {
        UserProfile user = new UserProfile();
        user.setEmail("alice@example.com");
        user.setPassword("secret");
        user = userRepo.save(user);

        Optional<UserProfile> result = userRepo.findByEmail("alice@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(user.getId());
    }

    @Test
    void findByEmail_returns_empty_when_not_found() {
        Optional<UserProfile> result = userRepo.findByEmail("unknown@example.com");

        assertThat(result).isEmpty();
    }

    @Test
    void unique_email_constraint_is_enforced() {
        UserProfile u1 = new UserProfile();
        u1.setEmail("alice@example.com");
        u1.setPassword("secret");
        userRepo.saveAndFlush(u1);

        UserProfile u2 = new UserProfile();
        u2.setEmail("alice@example.com");
        u2.setPassword("other");

        assertThatThrownBy(() -> userRepo.saveAndFlush(u2))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void email_and_password_not_null_are_enforced() {
        UserProfile u = new UserProfile();
        u.setEmail(null);
        u.setPassword("x");
        assertThatThrownBy(() -> userRepo.saveAndFlush(u))
                .isInstanceOf(DataIntegrityViolationException.class);

        UserProfile v = new UserProfile();
        v.setEmail("nn@example.com");
        v.setPassword(null);
        assertThatThrownBy(() -> userRepo.saveAndFlush(v))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void repository_match_is_case_sensitive_as_stored() {
        UserProfile u = new UserProfile();
        u.setEmail("Alice@Example.com");
        u.setPassword("x");
        userRepo.saveAndFlush(u);

        assertThat(userRepo.existsByEmail("alice@example.com")).isFalse();
        assertThat(userRepo.existsByEmail("Alice@Example.com")).isTrue();
    }

    @Test
    void user_roles_persist_and_delete_user_keeps_roles() {
        Role admin = new com.pm.userservice.domain.auth.Role();
        admin.setCode("ADMIN");
        admin = roleRepo.saveAndFlush(admin);

        UserProfile user = new UserProfile();
        user.setEmail("roles@example.com");
        user.setPassword("pw");
        user.getRoles().add(admin);
        var saved = userRepo.saveAndFlush(user);

        var reloaded = userRepo.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getRoles()).extracting(com.pm.userservice.domain.auth.Role::getCode)
                .containsExactly("ADMIN");

        userRepo.deleteById(saved.getId());
        userRepo.flush();

        // Role entity remains (no cascade REMOVE on roles)
        assertThat(roleRepo.findByCode("ADMIN")).isPresent();
    }
}
