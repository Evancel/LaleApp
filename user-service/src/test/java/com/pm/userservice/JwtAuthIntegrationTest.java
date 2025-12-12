package com.pm.userservice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.dto.auth.LoginResponseDTO;
import com.pm.userservice.dto.user.UserResponseDTO;
import com.pm.userservice.repository.user.UserProfileRepository;
import com.pm.userservice.security.JwtService;
import com.pm.userservice.security.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "jwt.secret=testasdfghjkl-secret-1234567890-test-secret-XXX",
        "jwt.expiration-ms=900000"
})
@ActiveProfiles("test")
@AutoConfigureMockMvc
@Transactional
class JwtAuthIntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    UserProfileRepository userProfileRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtService jwtService;

    @Autowired
    ObjectMapper objectMapper;

    private UserProfile user;
    private String rawPassword = "SecretPass123!";
    private String email = "login@example.com";

    @BeforeEach
    void setUp() {
        user = new UserProfile();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);
        // set any other required fields on UserProfile here
        user = userProfileRepository.save(user);
    }

    @Test
    void login_withValidCredentials_returnsTokenAndUser() throws Exception {
        String body = """
            {
              "email": "%s",
              "password": "%s"
            }
            """.formatted(email, rawPassword);

        String json = mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.user.email").value(email))
                .andReturn()
                .getResponse()
                .getContentAsString();

        LoginResponseDTO response =
                objectMapper.readValue(json, LoginResponseDTO.class);

        assertThat(response.getToken()).isNotBlank();
        assertThat(response.getUser().getEmail()).isEqualTo(email);
    }

    @Test
    void getCurrentUser_withoutToken_returns401() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getCurrentUser_withInvalidToken_returns401() throws Exception {
        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer totally.invalid.token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getCurrentUser_withValidToken_returnsUser() throws Exception {
        // given: a valid JWT for this user
        UserPrincipal principal = new UserPrincipal(user);
        String token = jwtService.generateToken(principal);

        String json = mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andReturn()
                .getResponse()
                .getContentAsString();

        UserResponseDTO dto = objectMapper.readValue(json, UserResponseDTO.class);
        assertThat(dto.getId()).isEqualTo(user.getId());
        assertThat(dto.getEmail()).isEqualTo(email);
    }
}

