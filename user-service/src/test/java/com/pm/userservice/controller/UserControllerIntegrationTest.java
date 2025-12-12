package com.pm.userservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.userservice.domain.auth.EmailVerificationToken;
import com.pm.userservice.domain.auth.Role;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.dto.auth.LoginRequestDTO;
import com.pm.userservice.dto.auth.LoginResponseDTO;
import com.pm.userservice.dto.user.UserRequestDTO;
import com.pm.userservice.repository.auth.EmailVerificationTokenRepository;
import com.pm.userservice.repository.auth.RoleRepository;
import com.pm.userservice.repository.user.UserProfileRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class UserControllerIntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    UserProfileRepository userProfileRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    EmailVerificationTokenRepository emailVerificationTokenRepository;

    private Role userRole;
    private Role adminRole;

    @BeforeEach
    void setUp() {
        adminRole = roleRepository.findByCode("ADMIN")
                .orElseThrow(() -> new IllegalStateException("ADMIN role must exist (seeded by DataLoader)"));

        userRole = roleRepository.findByCode("USER")
                .orElseThrow(() -> new IllegalStateException("USER role must exist (seeded by DataLoader)"));
    }

    // ----------------------------------------
    // Helpers
    // ----------------------------------------

    private UserProfile createUser(String email, String rawPassword, Role... roles) {
        UserProfile user = new UserProfile();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);
        user.setAccountLocked(false);
        user.setRoles(new HashSet<>(Arrays.asList(roles)));
        return userProfileRepository.save(user);
    }

    private String loginAndGetToken(String email, String password) throws Exception {
        LoginRequestDTO req = new LoginRequestDTO();
        req.setEmail(email);
        req.setPassword(password);

        MvcResult result = mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();

        String json = result.getResponse().getContentAsString();
        LoginResponseDTO resp = objectMapper.readValue(json, LoginResponseDTO.class);
        return resp.getToken();
    }

    // ============================================================
    // /users/signup is permitAll & creates a user
    // ============================================================
    @Test
    @Tag("smoke")
    void signup_createsUser_andIsAccessibleWithoutAuthentication() throws Exception {
        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("alice@example.com");
        req.setPassword("StrongPassword123!");
        req.setRole("USER");

        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("/users/signup/")));

        // verify user really persisted
        List<UserProfile> all = userProfileRepository.findAll();
        assertThat(all).hasSize(1);
        UserProfile stored = all.get(0);
        assertThat(stored.getEmail()).isEqualTo("alice@example.com");
        assertThat(passwordEncoder.matches("StrongPassword123!", stored.getPassword())).isTrue();
        assertThat(stored.getRoles()).extracting(Role::getCode).containsExactly("USER");
    }

    @Test
    void signup_withExistingEmail_returnsBadRequestAndErrorBody() throws Exception {
        // given existing user with this email
        createUser("duplicate@example.com", "Existing_password123", userRole);

        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("duplicate@example.com");
        req.setPassword("New_password123!");
        req.setRole("USER");

        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email already exists"));

        // and DB still contains only the original user
        var all = userProfileRepository.findAll();
        assertThat(all).hasSize(1);
        assertThat(all.get(0).getEmail()).isEqualTo("duplicate@example.com");
    }

    // ============================================================
    // /users/login is permitAll & login a user
    // ============================================================
    @Test
    void login_withValidCredentials_returnsTokenAndUserDto() throws Exception {
        // given existing user in DB
        UserProfile user = createUser("login@example.com", "secret-pass", userRole);

        LoginRequestDTO req = new LoginRequestDTO();
        req.setEmail("login@example.com");
        req.setPassword("secret-pass");

        mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.user.id").value(user.getId().toString()))
                .andExpect(jsonPath("$.user.email").value("login@example.com"));
    }

    @Test
    void login_withInvalidCredentials_returns401() throws Exception {
        LoginRequestDTO req = new LoginRequestDTO();
        req.setEmail("unknown@example.com");
        req.setPassword("wrong-pass");

        mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.auth").value("invalid email or password"));
    }

    // ============================================================
    // GET /users/me
    // ============================================================
    @Test
    void getCurrentUser_returnsProfileOfAuthenticatedUser() throws Exception {
        UserProfile user = createUser("me@example.com", "me-pass", userRole);
        String token = loginAndGetToken("me@example.com", "me-pass");

        mockMvc.perform(get("/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(user.getId().toString()))
                .andExpect(jsonPath("$.email").value("me@example.com"));
    }

    // ============================================================
    // GET /users (admin only)
    // ============================================================
    @Test
    void getUsers_unauthenticated_returns401() throws Exception {
        mockMvc.perform(get("/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getUsers_authenticatedAsUser_returns403() throws Exception {
        createUser("user@example.com", "user-pass", userRole);
        String token = loginAndGetToken("user@example.com", "user-pass");

        mockMvc.perform(get("/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));
    }

    @Test
    @Tag("smoke")
    void getUsers_authenticatedAsAdmin_returns200_andListsUsers() throws Exception {
        createUser("admin@example.com", "admin-pass", adminRole);
        createUser("alice@example.com", "alice-pass", userRole);
        createUser("bob@example.com", "bob-pass", userRole);
        String token = loginAndGetToken("admin@example.com", "admin-pass");

        mockMvc.perform(get("/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "3"))
                .andExpect(jsonPath("$[0].email").exists());
    }

    // ============================================================
    // GET /users/{id} with @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    // ============================================================
    @Test
    @Tag("smoke")
    void getUser_asOwner_returns200() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);
        String token = loginAndGetToken("owner@example.com", "owner-pass");

        mockMvc.perform(get("/users/{id}", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(owner.getId().toString()))
                .andExpect(jsonPath("$.email").value("owner@example.com"));
    }

    @Test
    void getUser_asDifferentUser_returns403() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);
        createUser("other@example.com", "other-pass", userRole);
        String token = loginAndGetToken("other@example.com", "other-pass");

        mockMvc.perform(get("/users/{id}", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));
    }

    @Test
    void getUser_asAdmin_canAccessAnyUser_returns200() throws Exception {
        UserProfile target = createUser("user@example.com", "user-pass", userRole);
        createUser("admin@example.com", "admin-pass", adminRole);
        String token = loginAndGetToken("admin@example.com", "admin-pass");

        mockMvc.perform(get("/users/{id}", target.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(target.getId().toString()))
                .andExpect(jsonPath("$.email").value("user@example.com"));
    }

    // ----------------------------------------
    // PATCH /users/{id}
    // ----------------------------------------
    @Test
    void patchUser_unauthenticated_returns401() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);

        mockMvc.perform(patch("/users/{id}", owner.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"new-owner@example.com"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void patchUser_asDifferentUser_returns403_andDoesNotChangeData() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);
        createUser("other@example.com", "other-pass", userRole);
        String token = loginAndGetToken("other@example.com", "other-pass");

        mockMvc.perform(patch("/users/{id}", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"new-owner@example.com"}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));

        // verify email was NOT changed
        UserProfile reloaded = userProfileRepository.findById(owner.getId()).orElseThrow();
        assertThat(reloaded.getEmail()).isEqualTo("owner@example.com");
    }

    @Test
    void patchUser_asOwner_updatesOwnName_returns200() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);
        owner.setName("Old Name");
        userProfileRepository.save(owner);

        String token = loginAndGetToken("owner@example.com", "owner-pass");

        mockMvc.perform(patch("/users/{id}", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"New Owner Name"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(owner.getId().toString()))
                .andExpect(jsonPath("$.email").value("owner@example.com")); // email unchanged

        UserProfile updated = userProfileRepository.findById(owner.getId()).orElseThrow();
        assertThat(updated.getName()).isEqualTo("New Owner Name");
    }

    @Test
    void patchUser_asAdmin_canUpdateAnyUserName_returns200() throws Exception {
        UserProfile target = createUser("user@example.com", "user-pass", userRole);
        target.setName("Old Name");
        userProfileRepository.save(target);

        createUser("admin@example.com", "admin-pass", adminRole);
        String token = loginAndGetToken("admin@example.com", "admin-pass");

        mockMvc.perform(patch("/users/{id}", target.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Updated By Admin"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(target.getId().toString()))
                .andExpect(jsonPath("$.email").value("user@example.com"));

        UserProfile updated = userProfileRepository.findById(target.getId()).orElseThrow();
        assertThat(updated.getName()).isEqualTo("Updated By Admin");
    }

    // ----------------------------------------
    // PATCH /users/{id}/email
    // ----------------------------------------
    @Test
    @Transactional
    void changeEmail_withCorrectPassword_changesEmailAndDisablesUser() throws Exception {
        // given existing user in DB
        UserProfile user = createUser("old@example.com", "CurrentPass123!", userRole);
        String token = loginAndGetToken("old@example.com", "CurrentPass123!");

        String body = """
                {
                  "newEmail": "new.example@example.com",
                  "currentPassword": "CurrentPass123!"
                }
                """;

        mockMvc.perform(patch("/users/{id}/email", user.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNoContent());

        // then: reload from DB and assert
        UserProfile reloaded = userProfileRepository.findById(user.getId())
                .orElseThrow();

        assertThat(reloaded.getEmail()).isEqualTo("new.example@example.com");
        assertThat(reloaded.isEnabled()).isFalse();
    }

    @Test
    @Transactional
    void changeEmail_withWrongPassword_returnsUnauthorizedOrBadCredentials() throws Exception {
        UserProfile user = createUser("old@example.com", "RightPass123!", userRole);
        String token = loginAndGetToken("old@example.com", "RightPass123!");

        String body = """
                {
                  "newEmail": "new.example@example.com",
                  "currentPassword": "WrongPass999!"
                }
                """;

        mockMvc.perform(patch("/users/{id}/email", user.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());

        UserProfile reloaded = userProfileRepository.findById(user.getId())
                .orElseThrow();

        // email should not change
        assertThat(reloaded.getEmail()).isEqualTo("old@example.com");
        assertThat(reloaded.isEnabled()).isTrue();
    }

    // ----------------------------------------
    // PATCH /users/{id}/password
    // ----------------------------------------
    @Test
    void changePassword_asOwner_withCorrectOldPassword_updatesPassword() throws Exception {
        UserProfile owner = createUser("owner-pass@example.com", "Old_password123", userRole);
        String token = loginAndGetToken("owner-pass@example.com", "Old_password123");

        mockMvc.perform(patch("/users/{id}/password", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"oldPassword":"Old_password123","newPassword":"New_password123"}
                                """))
                .andExpect(status().isNoContent());

        UserProfile updated = userProfileRepository.findById(owner.getId()).orElseThrow();
        assertThat(passwordEncoder.matches("New_password123", updated.getPassword())).isTrue();
    }

    @Test
    void changePassword_asOwner_withWrongOldPassword_returnsBadRequest() throws Exception {
        UserProfile owner = createUser("owner-pass@example.com", "Old_password123", userRole);
        String token = loginAndGetToken("owner-pass@example.com", "Old_password123");

        mockMvc.perform(patch("/users/{id}/password", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"oldPassword":"Old_password125","newPassword":"New_password123"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Credentials are wrong"));
    }

    @Test
    void changePassword_asDifferentUser_returnsForbidden() throws Exception {
        UserProfile owner = createUser("owner-pass@example.com", "Old_password123", userRole);
        createUser("other@example.com", "Other_password123", userRole);
        String token = loginAndGetToken("other@example.com", "Other_password123");

        mockMvc.perform(patch("/users/{id}/password", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"oldPassword":"Doesnt_matter987","newPassword":"New_password123"}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));
    }

    // ============================================================
    // DELETE /users/{id} - @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    // ============================================================
    @Test
    void deleteUser_unauthenticated_returns401() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);

        mockMvc.perform(delete("/users/{id}", owner.getId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteUser_asDifferentUser_returns403_andDoesNotDelete() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);
        createUser("other@example.com", "other-pass", userRole);
        String token = loginAndGetToken("other@example.com", "other-pass");

        mockMvc.perform(delete("/users/{id}", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));

        assertThat(userProfileRepository.existsById(owner.getId())).isTrue();
    }

    @Test
    void deleteUser_asOwner_deletesOwnAccount_returns204() throws Exception {
        UserProfile owner = createUser("owner@example.com", "owner-pass", userRole);
        String token = loginAndGetToken("owner@example.com", "owner-pass");

        mockMvc.perform(delete("/users/{id}", owner.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNoContent());

        assertThat(userProfileRepository.existsById(owner.getId())).isFalse();
    }

    @Test
    void deleteUser_asAdmin_canDeleteAnyUser_returns204() throws Exception {
        UserProfile target = createUser("user@example.com", "user-pass", userRole);
        createUser("admin@example.com", "admin-pass", adminRole);
        String token = loginAndGetToken("admin@example.com", "admin-pass");

        mockMvc.perform(delete("/users/{id}", target.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNoContent());

        assertThat(userProfileRepository.existsById(target.getId())).isFalse();
    }

    // ----------------------------------------
    // Email verification
    // ----------------------------------------
    @Test
    void signup_createsDisabledUser_andVerificationToken() throws Exception {
        // given role USER exists from @BeforeEach

        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("verifyme@example.com");
        req.setPassword("Strong_password123!");
        req.setRole("USER");

        // when
        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("/users/signup/")));

        // then: user is saved and disabled
        List<UserProfile> users = userProfileRepository.findAll();
        assertThat(users).hasSize(1);
        UserProfile user = users.get(0);
        assertThat(user.getEmail()).isEqualTo("verifyme@example.com");
        assertThat(user.isEnabled()).isFalse(); // ⬅️ important

        // and: exactly one verification token exists for that user
        List<EmailVerificationToken> tokens = emailVerificationTokenRepository.findAll();
        assertThat(tokens).hasSize(1);
        EmailVerificationToken token = tokens.get(0);

        assertThat(token.getUser().getId()).isEqualTo(user.getId());
        assertThat(token.isUsed()).isFalse();
        assertThat(token.getExpiresAt()).isAfter(Instant.now());
    }

    @Test
    void verifyEmail_enablesUser_andMarksTokenUsed() throws Exception {
        // 1) signup first
        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("verifyme2@example.com");
        req.setPassword("Strong_password123!");
        req.setRole("USER");

        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());

        // fetch user + token from DB
        UserProfile user = userProfileRepository.findAll().getFirst();
        EmailVerificationToken token = emailVerificationTokenRepository.findAll().getFirst();

        assertThat(user.isEnabled()).isFalse();
        assertThat(token.isUsed()).isFalse();

        // 2) call verify-email endpoint
        mockMvc.perform(get("/auth/verify-email")
                        .param("token", token.getToken()))
                .andExpect(status().isNoContent());

        // 3) reload from DB and assert changes
        UserProfile reloadedUser = userProfileRepository.findById(user.getId()).orElseThrow();
        EmailVerificationToken reloadedToken = emailVerificationTokenRepository.findById(token.getId()).orElseThrow();

        assertThat(reloadedUser.isEnabled()).isTrue();
        assertThat(reloadedToken.isUsed()).isTrue();
    }

    @Test
    void verifyEmail_withInvalidToken_returnsBadRequest() throws Exception {
        // sanity: no tokens in DB
        assertThat(emailVerificationTokenRepository.findAll()).isEmpty();

        mockMvc.perform(get("/auth/verify-email")
                        .param("token", "non-existing-token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.token").value("Invalid or expired verification link"));
    }

    // ============================================================
    // REAL FLOW 1:
    //   1. Signs up the user
    //   2. Asserts user is created & disabled
    //   3. Asserts a verification token exists
    //   4. Calls /auth/verify-email to enable the user
    //   5. Then does GET → PATCH → GET as before
    // ============================================================
    @Test
    void userFlow_signup_verifyEmail_thenGetAndPatchOwnProfileName() throws Exception {
        // --- step 1: signup as USER (no auth) ---
        UserRequestDTO req = new UserRequestDTO();
        req.setEmail("flow-user@example.com");
        req.setPassword("FlowPassword123!");
        req.setRole("USER");

        MvcResult signupResult = mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("/users/signup/")))
                .andReturn();

        String location = signupResult.getResponse().getHeader("Location");
        assertThat(location).isNotNull();
        String idStr = location.substring(location.lastIndexOf('/') + 1);
        UUID userId = UUID.fromString(idStr);

        // user exists in DB and is DISABLED after signup
        UserProfile stored = userProfileRepository.findById(userId).orElseThrow();
        assertThat(stored.getEmail()).isEqualTo("flow-user@example.com");
        assertThat(stored.isEnabled()).isFalse();

        // verification token exists for this user
        EmailVerificationToken token = emailVerificationTokenRepository.findAll().get(0);
        assertThat(token.getUser().getId()).isEqualTo(userId);
        assertThat(token.isUsed()).isFalse();

        // --- step 2: verify email ---
        mockMvc.perform(get("/auth/verify-email")
                        .param("token", token.getToken()))
                .andExpect(status().isNoContent());

        // reload user & token after verification
        stored = userProfileRepository.findById(userId).orElseThrow();
        token = emailVerificationTokenRepository.findById(token.getId()).orElseThrow();

        assertThat(stored.isEnabled()).isTrue();
        assertThat(token.isUsed()).isTrue();

        // --- step 3: GET /users/{id} as owner (now enabled) ---
        String jwtToken = loginAndGetToken("flow-user@example.com", "FlowPassword123!");
        mockMvc.perform(get("/users/{id}", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("flow-user@example.com"));

        // --- step 4: PATCH own name ---
        mockMvc.perform(patch("/users/{id}", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Flow User New Name"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("flow-user@example.com"));

        UserProfile updated = userProfileRepository.findById(userId).orElseThrow();
        assertThat(updated.getName()).isEqualTo("Flow User New Name");

        // --- step 5: GET /users/{id} again with same credentials ---
        mockMvc.perform(get("/users/{id}", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("flow-user@example.com"));
    }

    // ============================================================
    // REAL FLOW 2:
    // admin + user exist -> admin GET /users/{id}
    // -> admin DELETE /users/{id} -> admin GET /users/{id} again -> 400 User not found
    // ============================================================

    @Test
    void adminFlow_getThenDeleteUser_thenSubsequentGetFails() throws Exception {
        // create admin and regular user directly in DB
        UserProfile admin = createUser("admin-flow@example.com", "admin-pass", adminRole);
        UserProfile target = createUser("victim@example.com", "victim-pass", userRole);

        // login as admin and get JWT
        String adminToken = loginAndGetToken("admin-flow@example.com", "admin-pass");

        // --- step 1: admin can GET the target user ---
        mockMvc.perform(get("/users/{id}", target.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(target.getId().toString()))
                .andExpect(jsonPath("$.email").value("victim@example.com"));

        // --- step 2: admin DELETEs the target user ---
        mockMvc.perform(delete("/users/{id}", target.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        assertThat(userProfileRepository.existsById(target.getId())).isFalse();

        // --- step 3: admin tries to GET the same user -> UserNotFoundException -> 404 by ApiExceptionHandler ---
        mockMvc.perform(get("/users/{id}", target.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.user").value("User not found"));
    }
}


