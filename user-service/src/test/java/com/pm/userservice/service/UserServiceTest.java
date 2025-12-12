package com.pm.userservice.service;

import com.pm.userservice.dto.user.*;
import com.pm.userservice.mail.EmailSender;
import com.pm.userservice.domain.auth.Role;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.exception.*;
import com.pm.userservice.mapper.UserMapper;
import com.pm.userservice.repository.auth.EmailVerificationTokenRepository;
import com.pm.userservice.repository.auth.RoleRepository;
import com.pm.userservice.repository.user.UserProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock UserProfileRepository userProfileRepository;
    @Mock RoleRepository roleRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock UserMapper userMapper;
    @Mock EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Mock EmailSender emailSender;

    UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userProfileRepository,
                emailVerificationTokenRepository,
                roleRepository,
                passwordEncoder,
                userMapper,
                emailSender);
    }

    // ============================================================
    // getUserById
    // ============================================================

    @Test
    void getUserById_returns_dto_when_found() {
        UUID id = UUID.randomUUID();
        UserProfile entity = new UserProfile();
        UserResponseDTO dto = new UserResponseDTO();

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(entity));
        when(userMapper.toDto(entity)).thenReturn(dto);

        UserResponseDTO result = userService.getUserById(id);

        assertThat(result).isSameAs(dto);
        verify(userProfileRepository).findById(id);
        verify(userMapper).toDto(entity);
    }

    @Test
    void getUserById_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(userProfileRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUserById(id))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessage("User not found with id = " + id);
    }

    // ============================================================
    // addUser
    // ============================================================

    @Test
    void addUser_creates_user_when_email_unique_and_role_exists() {
        UserRequestDTO req = new UserRequestDTO();
        req.setEmail(" Alice@example.com ");
        req.setPassword("secret");
        req.setRole(" admin ");

        when(userProfileRepository.existsByEmail("alice@example.com")).thenReturn(false);

        Role role = new Role();
        role.setCode("ADMIN");
        when(roleRepository.findByCode("ADMIN")).thenReturn(Optional.of(role));

        when(passwordEncoder.encode("secret")).thenReturn("ENC");

        UserProfile saved = new UserProfile();
        saved.setEmail("alice@example.com");
        when(userProfileRepository.save(any(UserProfile.class))).thenReturn(saved);

        UserResponseDTO dto = new UserResponseDTO();
        when(userMapper.toDto(saved)).thenReturn(dto);

        UserResponseDTO result = userService.addUser(req);

        assertThat(result).isSameAs(dto);

        ArgumentCaptor<UserProfile> captor = ArgumentCaptor.forClass(UserProfile.class);
        verify(userProfileRepository).save(captor.capture());
        UserProfile toSave = captor.getValue();

        assertThat(toSave.getEmail()).isEqualTo("alice@example.com");
        assertThat(toSave.getPassword()).isEqualTo("ENC");
        assertThat(toSave.getRoles()).containsExactly(role);
    }

    @Test
    void addUser_throws_when_email_already_exists_precheck() {
        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("  new@example.com  ");
        req.setPassword("secret");
        req.setRole("ADMIN");

        when(userProfileRepository.existsByEmail("new@example.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.addUser(req))
                .isInstanceOf(EmailAlreadyExistsException.class)
                .hasMessage("User with this email new@example.com already exists");

        verify(roleRepository, never()).findByCode(anyString());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userProfileRepository, never()).save(any(UserProfile.class));
        verify(userMapper, never()).toDto(any());
    }

    @Test
    void addUser_throws_when_role_not_found() {
        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("user@example.com");
        req.setPassword("secret");
        req.setRole("MISSING");

        when(userProfileRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(roleRepository.findByCode("MISSING")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.addUser(req))
                .isInstanceOf(RoleNotFoundException.class)
                .hasMessage("Role not found with code = MISSING");

        verify(userProfileRepository, never()).save(any());
    }

    // ============================================================
    // updateUser - profile only (name)
    // ============================================================

    @Test
    void updateUser_sets_trimmed_name_and_saves() {
        UUID id = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setName("Old Name");

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(userProfileRepository.save(user)).thenReturn(user);

        UserResponseDTO dto = new UserResponseDTO();
        when(userMapper.toDto(user)).thenReturn(dto);

        UserPatchDTO patch = new UserPatchDTO(Optional.of("  New Name  "));

        UserResponseDTO result = userService.updateUser(id, patch);

        assertThat(result).isSameAs(dto);
        assertThat(user.getName()).isEqualTo("New Name");
        verify(userProfileRepository).save(user);
    }

    @Test
    void updateUser_blank_name_is_ignored() {
        UUID id = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setName("Old Name");

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(userProfileRepository.save(user)).thenReturn(user);
        when(userMapper.toDto(user)).thenReturn(new UserResponseDTO());

        UserPatchDTO patch = new UserPatchDTO(Optional.of("   "));

        userService.updateUser(id, patch);

        assertThat(user.getName()).isEqualTo("Old Name");
    }

    @Test
    void updateUser_null_optional_name_does_nothing() {
        UUID id = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setName("Old Name");

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(userProfileRepository.save(user)).thenReturn(user);
        when(userMapper.toDto(user)).thenReturn(new UserResponseDTO());

        UserPatchDTO patch = new UserPatchDTO(Optional.empty());

        userService.updateUser(id, patch);

        assertThat(user.getName()).isEqualTo("Old Name");
    }

    // ============================================================
    // changePassword
    // ============================================================

    @Test
    void changePassword_success_resets_counters_and_updates_password() {
        UUID id = UUID.randomUUID();

        UserProfile user = new UserProfile();
        user.setPassword("ENC_OLD");
        user.setPasswordChangeFailedAttempts(3);
        user.setLastPasswordChangeFailedAt(Instant.now().minusSeconds(60));

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("old-pass", "ENC_OLD")).thenReturn(true);
        when(passwordEncoder.encode("new-pass")).thenReturn("ENC_NEW");

        PasswordChangeDTO dto = new PasswordChangeDTO("old-pass", "new-pass");

        userService.changePassword(id, dto);

        assertThat(user.getPassword()).isEqualTo("ENC_NEW");
        assertThat(user.getPasswordChangeFailedAttempts()).isZero();
        assertThat(user.getLastPasswordChangeFailedAt()).isNull();
        verify(userProfileRepository).save(user);
    }

    @Test
    void changePassword_wrong_old_increments_counters_and_throws() {
        UUID id = UUID.randomUUID();

        UserProfile user = new UserProfile();
        user.setPassword("ENC_OLD");
        user.setPasswordChangeFailedAttempts(2);
        user.setLastPasswordChangeFailedAt(null);

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-old", "ENC_OLD")).thenReturn(false);
        when(userProfileRepository.save(user)).thenReturn(user);

        PasswordChangeDTO dto = new PasswordChangeDTO("wrong-old", "new-pass");

        assertThatThrownBy(() -> userService.changePassword(id, dto))
                .isInstanceOf(WrongPasswordException.class)
                .hasMessage("Old password does not match");

        assertThat(user.getPasswordChangeFailedAttempts()).isEqualTo(3);
        assertThat(user.getLastPasswordChangeFailedAt()).isNotNull();
        // password should not be changed
        assertThat(user.getPassword()).isEqualTo("ENC_OLD");
        verify(userProfileRepository).save(user);
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void changePassword_too_many_attempts_throws_lock_exception() {
        UUID id = UUID.randomUUID();

        UserProfile user = new UserProfile();
        user.setPassword("ENC_OLD");
        user.setPasswordChangeFailedAttempts(5); // >= MAX_FAILED_ATTEMPTS
        user.setLastPasswordChangeFailedAt(Instant.now()); // within LOCK_WINDOW

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));

        PasswordChangeDTO dto = new PasswordChangeDTO("old-pass", "new-pass");

        assertThatThrownBy(() -> userService.changePassword(id, dto))
                .isInstanceOf(TooManyPasswordChangeAttemptsException.class)
                .hasMessageContaining("Too many failed attempts");

        // no extra attempts, no save, no encode
        verify(userProfileRepository, never()).save(any());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void changePassword_user_not_found_throws() {
        UUID id = UUID.randomUUID();
        when(userProfileRepository.findById(id)).thenReturn(Optional.empty());

        PasswordChangeDTO dto = new PasswordChangeDTO("old", "new");

        assertThatThrownBy(() -> userService.changePassword(id, dto))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessage("User not found with id = " + id);
    }

    // ============================================================
    // updateUserRoles
    // ============================================================

    @Test
    void updateUserRoles_replaces_roles_normalized_and_saves() {
        UUID id = UUID.randomUUID();
        UserProfile user = new UserProfile();

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));

        Role admin = new Role();
        admin.setCode("ADMIN");
        Role basic = new Role();
        basic.setCode("USER");
        when(roleRepository.findByCode("ADMIN")).thenReturn(Optional.of(admin));
        when(roleRepository.findByCode("USER")).thenReturn(Optional.of(basic));

        when(userProfileRepository.save(user)).thenReturn(user);
        when(userMapper.toDto(user)).thenReturn(new UserResponseDTO());

        UserRolesUpdateDTO dto = new UserRolesUpdateDTO(List.of(" admin ", "USER", "", "admin"));

        userService.updateUserRoles(id, dto);

        assertThat(user.getRoles()).containsExactly(admin, basic);
    }

    @Test
    void updateUserRoles_only_blanks_clears_roles() {
        UUID id = UUID.randomUUID();
        UserProfile user = new UserProfile();
        Role r = new Role();
        r.setCode("ADMIN");
        user.getRoles().add(r);

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(userProfileRepository.save(user)).thenReturn(user);
        when(userMapper.toDto(user)).thenReturn(new UserResponseDTO());

        UserRolesUpdateDTO dto = new UserRolesUpdateDTO(List.of("  ", "\t"));

        userService.updateUserRoles(id, dto);

        assertThat(user.getRoles()).isEmpty();
    }

    @Test
    void updateUserRoles_role_not_found_throws_and_does_not_save() {
        UUID id = UUID.randomUUID();
        UserProfile user = new UserProfile();

        when(userProfileRepository.findById(id)).thenReturn(Optional.of(user));
        when(roleRepository.findByCode("ADMIN")).thenReturn(Optional.of(new Role()));
        when(roleRepository.findByCode("MISSING")).thenReturn(Optional.empty());

        UserRolesUpdateDTO dto = new UserRolesUpdateDTO(List.of("ADMIN", "MISSING"));

        assertThatThrownBy(() -> userService.updateUserRoles(id, dto))
                .isInstanceOf(RoleNotFoundException.class)
                .hasMessage("Role not found with code = MISSING");

        verify(userProfileRepository, never()).save(any());
        verify(userMapper, never()).toDto(any());
    }

    // ============================================================
    // deleteUser
    // ============================================================

    @Test
    void deleteUser_deletes_when_exists() {
        UUID id = UUID.randomUUID();
        when(userProfileRepository.existsById(id)).thenReturn(true);

        userService.deleteUser(id);

        verify(userProfileRepository).deleteById(id);
    }

    @Test
    void deleteUser_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(userProfileRepository.existsById(id)).thenReturn(false);

        assertThatThrownBy(() -> userService.deleteUser(id))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessage("User not found with id = " + id);

        verify(userProfileRepository, never()).deleteById(any());
    }
}