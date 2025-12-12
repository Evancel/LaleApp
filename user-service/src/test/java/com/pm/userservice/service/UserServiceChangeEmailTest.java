package com.pm.userservice.service;

import com.pm.userservice.dto.user.EmailChangeDTO;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.domain.auth.EmailVerificationToken;
import com.pm.userservice.exception.EmailAlreadyExistsException;
import com.pm.userservice.exception.EmailIsTheSame;
import com.pm.userservice.exception.UserNotFoundException;
import com.pm.userservice.mail.EmailSender;
import com.pm.userservice.repository.user.UserProfileRepository;
import com.pm.userservice.repository.auth.EmailVerificationTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Template tests for UserService.changeEmail(...)
 * Adjust package & imports to your project structure.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceChangeEmailTest {

    @Mock
    private UserProfileRepository userProfileRepository;

    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailSender emailSender;

    // If your UserService has more deps, add @Mock fields and
    // they will be injected into this @InjectMocks.
    @InjectMocks
    private UserService userService;

    @Test
    void changeEmail_success_updatesEmail_createsToken_sendsEmail() {
        // given
        UUID userId = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setEmail("old@example.com");
        user.setPassword("hashed-password");
        user.setEnabled(true);

        when(userProfileRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("CurrentPass123!", "hashed-password")).thenReturn(true);
        when(userProfileRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userProfileRepository.save(any(UserProfile.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // adjust constructor order if your record is (currentPassword, newEmail)
        EmailChangeDTO dto = new EmailChangeDTO("new@example.com", "CurrentPass123!");

        // when
        userService.changeEmail(userId, dto);

        // then: user updated & disabled
        ArgumentCaptor<UserProfile> userCaptor = ArgumentCaptor.forClass(UserProfile.class);
        verify(userProfileRepository).save(userCaptor.capture());
        UserProfile saved = userCaptor.getValue();

        assertThat(saved.getEmail()).isEqualTo("new@example.com");
        assertThat(saved.isEnabled()).isFalse();

        // token created and saved
        ArgumentCaptor<EmailVerificationToken> tokenCaptor =
                ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());

        EmailVerificationToken token = tokenCaptor.getValue();
        assertThat(token.getUser()).isEqualTo(saved);
        assertThat(token.getExpiresAt()).isAfter(Instant.now());

        // email sent with verification link
        ArgumentCaptor<String> toCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> linkCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender).sendEmailVerification(toCaptor.capture(), linkCaptor.capture());

        assertThat(toCaptor.getValue()).isEqualTo("new@example.com");
        assertThat(linkCaptor.getValue())
                .contains("/auth/verify-email?token="); // token is included in link
    }

    @Test
    void changeEmail_userNotFound_throwsUserNotFoundException() {
        // given
        UUID userId = UUID.randomUUID();
        when(userProfileRepository.findById(userId)).thenReturn(Optional.empty());
        EmailChangeDTO dto = new EmailChangeDTO("new@example.com", "pass");

        // when / then
        assertThrows(UserNotFoundException.class,
                () -> userService.changeEmail(userId, dto));

        verifyNoInteractions(passwordEncoder, emailSender, emailVerificationTokenRepository);
    }

    @Test
    void changeEmail_wrongPassword_throwsBadCredentialsException() {
        // given
        UUID userId = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setEmail("old@example.com");
        user.setPassword("hashed");
        when(userProfileRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-pass", "hashed")).thenReturn(false);

        EmailChangeDTO dto = new EmailChangeDTO("new@example.com", "wrong-pass");

        // when / then
        assertThrows(BadCredentialsException.class,
                () -> userService.changeEmail(userId, dto));

        verify(userProfileRepository, never()).save(any());
        verifyNoInteractions(emailSender, emailVerificationTokenRepository);
    }

    @Test
    void changeEmail_sameEmail_throwsEmailIsTheSame() {
        // given
        UUID userId = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setEmail("same@example.com");
        user.setPassword("hashed");

        when(userProfileRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("CurrentPass123!", "hashed")).thenReturn(true);

        // dto has the same email as current one
        EmailChangeDTO dto = new EmailChangeDTO("same@example.com", "CurrentPass123!");

        // when / then
        assertThrows(EmailIsTheSame.class,
                () -> userService.changeEmail(userId, dto));

        verify(userProfileRepository, never()).save(any());
        verifyNoInteractions(emailSender, emailVerificationTokenRepository);
    }

    @Test
    void changeEmail_newEmailAlreadyExists_throwsEmailAlreadyExistsException() {
        // given
        UUID userId = UUID.randomUUID();
        UserProfile user = new UserProfile();
        user.setEmail("old@example.com");
        user.setPassword("hashed");

        when(userProfileRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("CurrentPass123!", "hashed")).thenReturn(true);
        when(userProfileRepository.existsByEmail("taken@example.com")).thenReturn(true);

        EmailChangeDTO dto = new EmailChangeDTO("taken@example.com", "CurrentPass123!");

        // when / then
        assertThrows(EmailAlreadyExistsException.class,
                () -> userService.changeEmail(userId, dto));

        verify(userProfileRepository, never()).save(any());
        verifyNoInteractions(emailSender, emailVerificationTokenRepository);
    }
}

