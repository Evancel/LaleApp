package com.pm.userservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.userservice.config.SecurityConfig;
import com.pm.userservice.dto.user.UserPatchDTO;
import com.pm.userservice.dto.user.UserResponseDTO;
import com.pm.userservice.security.JpaUserDetailsServiceCustom;
import com.pm.userservice.security.JwtAuthenticationFilter;
import com.pm.userservice.security.JwtService;
import com.pm.userservice.security.UserPrincipal;
import com.pm.userservice.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = UserController.class)
@Import(SecurityConfig.class)
class UserControllerSecurityTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockBean
    UserService userService;

    @MockBean
    JpaUserDetailsServiceCustom jpaUserDetailsServiceCustom;

    @MockBean
    JwtService jwtService;

    @MockBean
    JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUpJwtFilterMock() throws Exception {
        // Make the mock behave as a "transparent" filter:
        // it just forwards the request to the rest of the chain.
        doAnswer(invocation -> {
            ServletRequest request = invocation.getArgument(0);
            ServletResponse response = invocation.getArgument(1);
            FilterChain chain = invocation.getArgument(2);
            chain.doFilter(request, response);
            return null;
        }).when(jwtAuthenticationFilter).doFilter(any(), any(), any());
    }


    // -------- helper principal with `id` property for SpEL --------

    static class TestPrincipal implements org.springframework.security.core.userdetails.UserDetails {
        private final UUID id;
        private final String username;
        private final Collection<? extends GrantedAuthority> authorities;

        TestPrincipal(UUID id, String username, Collection<? extends GrantedAuthority> authorities) {
            this.id = id;
            this.username = username;
            this.authorities = authorities;
        }

        public UUID getId() {
            return id;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public String getPassword() {
            return "password";
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }

    private TestPrincipal principal(UUID id, String username, String... roles) {
        List<SimpleGrantedAuthority> authorities = List.of(roles).stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .toList();
        return new TestPrincipal(id, username, authorities);
    }

    private UserResponseDTO sampleUser(UUID id, String email) {
        UserResponseDTO dto = new UserResponseDTO();
        dto.setId(id);
        dto.setEmail(email);
        return dto;
    }

    @Test
    void signup_permitAll_allowsUnauthenticatedUser() throws Exception {
        UUID id = UUID.randomUUID();

        UserResponseDTO saved = new UserResponseDTO();
        saved.setId(id);
        saved.setEmail("alice@example.com");

        given(userService.addUser(any())).willReturn(saved);

        Map<String, Object> requestBody = Map.of(
                "email", "alice@example.com",
                "password", "StrongPassword123!"
        );

        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isCreated());

        verify(userService).addUser(any());
    }

    // ============================================================
    // GET /users  (admin-only via @PreAuthorize("hasRole('ADMIN')"))
    // ============================================================

    @Test
    void getUsers_unauthenticated_returns401() throws Exception {
        mockMvc.perform(get("/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getUsers_authenticatedWithoutAdminRole_returns403() throws Exception {
        TestPrincipal userPrincipal =
                principal(UUID.randomUUID(), "user@example.com", "USER");

        mockMvc.perform(get("/users").with(user(userPrincipal)))
                .andExpect(status().isForbidden());
    }

    @Test
    void getUsers_authenticatedWithAdminRole_returns200() throws Exception {
        TestPrincipal adminPrincipal =
                principal(UUID.randomUUID(), "admin@example.com", "ADMIN");

        given(userService.getUsers(any())).willReturn(
                org.springframework.data.domain.Page.empty()
        );

        mockMvc.perform(get("/users").with(user(adminPrincipal)))
                .andExpect(status().isOk());

        verify(userService).getUsers(any());
    }

    // ============================================================
    // GET /users/me  (@PreAuthorize("isAuthenticated()"))
    // ============================================================

    @Test
    void getCurrentUser_authenticated_returns200() throws Exception {
        UUID id = UUID.randomUUID();

        UserPrincipal principal = mock(UserPrincipal.class);

        when(principal.getId()).thenReturn(id);
        when(principal.getUsername()).thenReturn("user@example.com");
        when(principal.getPassword()).thenReturn("ignored");

        Collection<? extends GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_USER"));
        doReturn(authorities).when(principal).getAuthorities();
        when(principal.isAccountNonExpired()).thenReturn(true);
        when(principal.isAccountNonLocked()).thenReturn(true);
        when(principal.isCredentialsNonExpired()).thenReturn(true);
        when(principal.isEnabled()).thenReturn(true);

        given(userService.getUserById(id))
                .willReturn(sampleUser(id, "user@example.com"));

        mockMvc.perform(get("/users/me").with(user(principal)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.email").value("user@example.com"));

        verify(userService).getUserById(id);
    }

    @Test
    void getCurrentUser_unauthenticated_returns401() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized());
    }

    // ============================================================
    // GET /users/{id}  (@PreAuthorize("#id == principal.id or hasRole('ADMIN')"))
    // ============================================================

    @Test
    void getUser_unauthenticated_returns401() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(get("/users/{id}", id))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getUser_authenticatedAsOtherUser_returns403() throws Exception {
        UUID loggedInId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();

        TestPrincipal principal =
                principal(loggedInId, "user@example.com", "USER");

        mockMvc.perform(get("/users/{id}", targetId).with(user(principal)))
                .andExpect(status().isForbidden());

        verify(userService, never()).getUserById(any());
    }

    @Test
    void getUser_authenticatedAsOwner_returns200() throws Exception {
        UUID id = UUID.randomUUID();

        TestPrincipal principal =
                principal(id, "owner@example.com", "USER");

        given(userService.getUserById(id))
                .willReturn(sampleUser(id, "owner@example.com"));

        mockMvc.perform(get("/users/{id}", id).with(user(principal)))
                .andExpect(status().isOk());

        verify(userService).getUserById(id);
    }

    @Test
    void getUser_authenticatedAsAdmin_returns200() throws Exception {
        UUID targetId = UUID.randomUUID();

        TestPrincipal adminPrincipal =
                principal(UUID.randomUUID(), "admin@example.com", "ADMIN");

        given(userService.getUserById(targetId))
                .willReturn(sampleUser(targetId, "user@example.com"));

        mockMvc.perform(get("/users/{id}", targetId).with(user(adminPrincipal)))
                .andExpect(status().isOk());

        verify(userService).getUserById(targetId);
    }

    // ============================================================
    // PATCH /users/{id}
    // ============================================================

    @Test
    void patchUser_unauthenticated_returns401() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(patch("/users/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"new@example.com\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void patchUser_authenticatedAsOtherUser_returns403() throws Exception {
        UUID loggedInId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();

        TestPrincipal principal =
                principal(loggedInId, "user@example.com", "USER");

        mockMvc.perform(patch("/users/{id}", targetId)
                        .with(user(principal))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"new@example.com\"}"))
                .andExpect(status().isForbidden());

        verify(userService, never()).updateUser(any(), any(UserPatchDTO.class));
    }

    @Test
    void patchUser_authenticatedAsOwner_returns200() throws Exception {
        UUID id = UUID.randomUUID();

        TestPrincipal principal =
                principal(id, "owner@example.com", "USER");

        UserResponseDTO updated = sampleUser(id, "new@example.com");

        given(userService.updateUser(eq(id), any(UserPatchDTO.class)))
                .willReturn(updated);

        mockMvc.perform(patch("/users/{id}", id)
                        .with(user(principal))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"new@example.com\"}"))
                .andExpect(status().isOk());

        verify(userService).updateUser(eq(id), any(UserPatchDTO.class));
    }

    @Test
    void patchUser_authenticatedAsAdmin_returns200() throws Exception {
        UUID targetId = UUID.randomUUID();

        TestPrincipal adminPrincipal =
                principal(UUID.randomUUID(), "admin@example.com", "ADMIN");

        UserResponseDTO updated = sampleUser(targetId, "admin-updated@example.com");

        given(userService.updateUser(eq(targetId), any(UserPatchDTO.class)))
                .willReturn(updated);

        mockMvc.perform(patch("/users/{id}", targetId)
                        .with(user(adminPrincipal))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin-updated@example.com\"}"))
                .andExpect(status().isOk());

        verify(userService).updateUser(eq(targetId), any(UserPatchDTO.class));
    }

    // ============================================================
    // DELETE /users/{id}
    // ============================================================

    @Test
    void deleteUser_unauthenticated_returns401() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(delete("/users/{id}", id))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteUser_authenticatedAsOtherUser_returns403() throws Exception {
        UUID loggedInId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();

        TestPrincipal principal =
                principal(loggedInId, "user@example.com", "USER");

        mockMvc.perform(delete("/users/{id}", targetId).with(user(principal)))
                .andExpect(status().isForbidden());

        verify(userService, never()).deleteUser(any());
    }

    @Test
    void deleteUser_authenticatedAsOwner_returns204() throws Exception {
        UUID id = UUID.randomUUID();

        TestPrincipal principal =
                principal(id, "owner@example.com", "USER");

        mockMvc.perform(delete("/users/{id}", id).with(user(principal)))
                .andExpect(status().isNoContent());

        verify(userService).deleteUser(id);
    }

    @Test
    void deleteUser_authenticatedAsAdmin_returns204() throws Exception {
        UUID targetId = UUID.randomUUID();

        TestPrincipal adminPrincipal =
                principal(UUID.randomUUID(), "admin@example.com", "ADMIN");

        mockMvc.perform(delete("/users/{id}", targetId).with(user(adminPrincipal)))
                .andExpect(status().isNoContent());

        verify(userService).deleteUser(targetId);
    }
}