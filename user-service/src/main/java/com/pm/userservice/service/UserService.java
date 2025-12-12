package com.pm.userservice.service;

import com.pm.userservice.dto.user.*;
import com.pm.userservice.mail.EmailSender;
import com.pm.userservice.domain.auth.EmailVerificationToken;
import com.pm.userservice.domain.auth.Role;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.domain.value.Email;
import com.pm.userservice.domain.value.RoleCode;
import com.pm.userservice.exception.*;
import com.pm.userservice.mapper.UserMapper;
import com.pm.userservice.repository.auth.EmailVerificationTokenRepository;
import com.pm.userservice.repository.auth.RoleRepository;
import com.pm.userservice.repository.user.UserProfileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static com.pm.userservice.logging.LoggingUtils.maskEmail;
import static com.pm.userservice.logging.LoggingUtils.maskToken;

//TODO: Domain messages and i18n
//Hard-coded English strings are fine for dev, but for production:
//Centralize error messages (constants or MessageSource).
//Use ProblemDetail in a @RestControllerAdvice for consistent error shapes.

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_WINDOW = Duration.ofMinutes(15);

    private final UserProfileRepository userProfileRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final EmailSender emailSender;

    public UserService(UserProfileRepository userProfileRepository,
                       EmailVerificationTokenRepository emailVerificationTokenRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       UserMapper userMapper,
                       EmailSender emailSender) {
        this.userProfileRepository = userProfileRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.emailSender = emailSender;
    }

    // ========================= READ METHODS =========================

    @Transactional(readOnly = true)
    public Page<UserResponseDTO> getUsers(Pageable pageable) {
        log.debug("Fetching users page={} size={} sort={}",
                pageable.getPageNumber(), pageable.getPageSize(), pageable.getSort());

        return userProfileRepository.findAll(pageable)
                .map(userMapper::toDto);
    }

    @Transactional(readOnly = true)
    public UserResponseDTO getUserById(UUID id) {
        log.debug("Fetching user by id={}", id);

        UserProfile userProfile = userProfileRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("User not found id={}", id);
                    return new UserNotFoundException("User not found with id = " + id);
                });

        return userMapper.toDto(userProfile);
    }

    // ========================= SIGNUP & EMAIL VERIFY =========================

    @Transactional
    public UserResponseDTO addUser(UserRequestDTO req) {
        Email email = Email.of(req.getEmail());
        RoleCode roleCode = RoleCode.of(req.getRole());

        log.info("User signup requested email={} role={}", maskEmail(email.raw()), roleCode.canonical());

        if (userProfileRepository.existsByEmail(email.canonical())) {
            log.warn("Signup rejected: email already exists email={}", maskEmail(email.raw()));
            throw new EmailAlreadyExistsException(
                    String.format("User with this email %s already exists", email.raw()));
        }

        Role role = roleRepository.findByCode(roleCode.canonical())
                .orElseThrow(() -> {
                    log.error("Signup failed: role not found code={}", roleCode.canonical());
                    return new RoleNotFoundException("Role not found with code = " + roleCode);
                });

        UserProfile newUserProfile = new UserProfile();
        newUserProfile.setEmail(email.canonical());
        newUserProfile.setPassword(passwordEncoder.encode(req.getPassword()));
        newUserProfile.setEnabled(false);  // until email verified
        newUserProfile.getRoles().add(role);

        try {
            UserProfile savedUserProfile = userProfileRepository.save(newUserProfile);

            // 1) create token
            String rawToken = UUID.randomUUID().toString();
            EmailVerificationToken token = new EmailVerificationToken();
            token.setToken(rawToken);
            token.setUser(savedUserProfile);
            token.setExpiresAt(Instant.now().plus(Duration.ofHours(24)));
            emailVerificationTokenRepository.save(token);

            // 2) build verification link
            String link = "http://localhost:8080/auth/verify-email?token=" + rawToken;

            // 3) send email
            emailSender.sendEmailVerification(savedUserProfile.getEmail(), link);

            log.info("User signup completed userId={} email={}",
                    savedUserProfile.getId(), maskEmail(savedUserProfile.getEmail()));

            return userMapper.toDto(savedUserProfile);

        } catch (DataIntegrityViolationException ex) {
            if (ExceptionUtils.isEmailUniqueViolation(ex)) {
                log.warn("Signup failed due to unique constraint email={}", maskEmail(email.raw()));
                throw new EmailAlreadyExistsException(
                        "User with this email " + email.raw() + " already exists");
            }
            log.error("Unexpected DataIntegrityViolationException during signup email={}",
                    maskEmail(email.raw()), ex);
            throw ex;
        }
    }

    @Transactional
    public void verifyEmail(String tokenValue) {
        log.info("Email verification attempt token={}", maskToken(tokenValue));

        EmailVerificationToken token = emailVerificationTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> {
                    log.warn("Email verification failed: token not found token={}", maskToken(tokenValue));
                    return new InvalidVerificationTokenException("Invalid token");
                });

        if (token.isUsed()) {
            log.warn("Email verification failed: token already used token={}", maskToken(tokenValue));
            throw new InvalidVerificationTokenException("Token already used");
        } else if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Email verification failed: token expired token={}", maskToken(tokenValue));
            throw new InvalidVerificationTokenException("Token expired");
        }

        UserProfile user = token.getUser();
        user.setEnabled(true);
        user.setEmailVerifiedAt(Instant.now());
        token.setUsed(true);

        userProfileRepository.save(user);
        emailVerificationTokenRepository.save(token);

        log.info("Email verified successfully userId={}", user.getId());
    }

    // ========================= PROFILE / EMAIL / PASSWORD =========================

    @Transactional
    public UserResponseDTO updateUser(UUID id, UserPatchDTO patch) {
        UserProfile user = userProfileRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Profile update failed: user not found id={}", id);
                    return new UserNotFoundException("User not found with id = " + id);
                });

        applyNamePatch(user, patch);

        UserProfile saved = userProfileRepository.save(user);
        log.info("Profile updated userId={}", id);

        return userMapper.toDto(saved);
    }

    @Transactional
    public void changeEmail(UUID id, EmailChangeDTO dto) {
        UserProfile user = userProfileRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Email change failed: user not found id={}", id);
                    return new UserNotFoundException("User not found with id = " + id);
                });

        log.info("Email change requested userId={} currentEmail={} newEmail={}",
                id, maskEmail(user.getEmail()), maskEmail(dto.newEmail()));

        // 1) Check password
        if (!passwordEncoder.matches(dto.currentPassword(), user.getPassword())) {
            log.warn("Email change rejected: wrong current password userId={}", id);
            throw new WrongPasswordException("Current password is incorrect");
        }

        Email newEmail = Email.of(dto.newEmail());

        if (newEmail.canonical().equalsIgnoreCase(user.getEmail())) {
            log.warn("Email change rejected: same email userId={} email={}",
                    id, maskEmail(newEmail.raw()));
            throw new EmailIsTheSame("New email must be different from current email");
        }

        if (userProfileRepository.existsByEmail(newEmail.canonical())) {
            log.warn("Email change rejected: email already in use userId={} newEmail={}",
                    id, maskEmail(newEmail.raw()));
            throw new EmailAlreadyExistsException(
                    String.format("Email already in use: %s", newEmail.raw()));
        }

        user.setEmail(newEmail.canonical());
        user.setEnabled(false);     // until email verified

        try {
            UserProfile savedUserProfile = userProfileRepository.save(user);

            // 1) create token
            String rawToken = UUID.randomUUID().toString();
            EmailVerificationToken token = new EmailVerificationToken();
            token.setToken(rawToken);
            token.setUser(savedUserProfile);
            token.setExpiresAt(Instant.now().plus(Duration.ofHours(24)));
            emailVerificationTokenRepository.save(token);

            // 2) build verification link
            String link = "http://localhost:8080/auth/verify-email?token=" + rawToken;

            // 3) send email
            emailSender.sendEmailVerification(savedUserProfile.getEmail(), link);

            log.info("Email change initiated userId={} newEmail={}",
                    id, maskEmail(savedUserProfile.getEmail()));

        } catch (DataIntegrityViolationException ex) {
            if (ExceptionUtils.isEmailUniqueViolation(ex)) {
                log.warn("Email change failed due to unique constraint userId={} newEmail={}",
                        id, maskEmail(newEmail.raw()));
                throw new EmailAlreadyExistsException(
                        "User with this email " + newEmail.raw() + " already exists");
            }
            log.error("Unexpected DataIntegrityViolationException during email change userId={}",
                    id, ex);
            throw ex;
        }
    }

    @Transactional
    public void changePassword(UUID id, PasswordChangeDTO dto) {
        UserProfile user = userProfileRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Password change failed: user not found id={}", id);
                    return new UserNotFoundException("User not found with id = " + id);
                });

        log.info("Password change requested userId={}", id);

        // check lock
        if (user.getPasswordChangeFailedAttempts() >= MAX_FAILED_ATTEMPTS &&
                user.getLastPasswordChangeFailedAt() != null &&
                user.getLastPasswordChangeFailedAt().isAfter(Instant.now().minus(LOCK_WINDOW))) {

            log.warn("Password change rejected: too many failed attempts userId={}", id);
            throw new TooManyPasswordChangeAttemptsException("Too many failed attempts. Try again later.");
        }

        String oldPassword = dto.oldPassword();
        String newPassword = dto.newPassword();

        // verify old password
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            user.setPasswordChangeFailedAttempts(user.getPasswordChangeFailedAttempts() + 1);
            user.setLastPasswordChangeFailedAt(Instant.now());
            userProfileRepository.save(user);

            log.warn("Password change rejected: wrong old password userId={} failedAttempts={}",
                    id, user.getPasswordChangeFailedAttempts());

            throw new WrongPasswordException("Old password does not match");
        }

        // success: reset counters
        user.setPasswordChangeFailedAttempts(0);
        user.setLastPasswordChangeFailedAt(null);

        applyPasswordPatch(user, newPassword);
        userProfileRepository.save(user);

        log.info("Password changed successfully userId={}", id);
    }

    // ========================= ROLES & DELETE =========================

    @Transactional
    public UserResponseDTO updateUserRoles(UUID id, UserRolesUpdateDTO dto) {
        UserProfile user = userProfileRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Role update failed: user not found id={}", id);
                    return new UserNotFoundException("User not found with id = " + id);
                });

        applyRolesPatch(user, dto.roles());

        UserProfile saved = userProfileRepository.save(user);

        log.info("User roles updated userId={} roles={}",
                id,
                saved.getRoles().stream()
                        .map(Role::getCode)
                        .collect(Collectors.toList()));

        return userMapper.toDto(saved);
    }

    @Transactional
    public void deleteUser(UUID id) {
        if (!userProfileRepository.existsById(id)) {
            log.warn("Delete user failed: user not found id={}", id);
            throw new UserNotFoundException("User not found with id = " + id);
        }

        log.info("Deleting user id={}", id);
        emailVerificationTokenRepository.deleteByUserId(id);
        userProfileRepository.deleteById(id);
        log.info("User deleted id={}", id);
    }

    // ========================= HELPERS =========================

    private void applyEmailPatch(UserProfile user, UUID userId, Email email) {
        String newCanon = email.canonical();
        String current = user.getEmail();

        // Skip if unchanged
        if (Objects.equals(current, newCanon)) {
            return;
        }

        if (userProfileRepository.existsByEmailAndIdNot(newCanon, userId)) {
            throw new EmailAlreadyExistsException("Email already in use: " + email.raw());
        }

        user.setEmail(newCanon);
    }

    private void applyNamePatch(UserProfile user, UserPatchDTO patch) {
        patch.name()
                .map(String::trim)
                .filter(trimmed -> !trimmed.isEmpty())
                .ifPresent(user::setName);
    }

    private void applyPasswordPatch(UserProfile user, String rawPassword) {
        if (rawPassword == null) {
            return;
        }

        String trimmed = rawPassword.trim();
        if (trimmed.isEmpty()) {
            return; // ignore blanks
        }

        String encoded = passwordEncoder.encode(trimmed);
        user.setPassword(encoded);
    }

    private void applyRolesPatch(UserProfile user, Collection<String> roleCodesRaw) {
        // normalize: trim, drop blanks, uppercase, dedupe (but keep order)
        Set<String> normalized = roleCodesRaw.stream()
                .map(code -> code == null ? "" : code.trim())
                .filter(s -> !s.isEmpty())
                .map(s -> s.toUpperCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));

        if (normalized.isEmpty()) {
            // explicit "empty list" means clear all roles
            user.getRoles().clear();
            return;
        }

        Set<Role> resolved = normalized.stream()
                .map(code -> roleRepository.findByCode(code)
                        .orElseThrow(() -> new RoleNotFoundException("Role not found with code = " + code)))
                .collect(Collectors.toCollection(LinkedHashSet::new));

        user.setRoles(resolved);
    }
}