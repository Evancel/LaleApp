package com.pm.userservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.userservice.advice.ApiExceptionHandler;
import com.pm.userservice.dto.user.*;
import com.pm.userservice.exception.*;
import com.pm.userservice.security.JpaUserDetailsServiceCustom;
import com.pm.userservice.security.JwtService;
import com.pm.userservice.security.UserPrincipal;
import com.pm.userservice.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.*;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false) // disable security filters for now
@Import(ApiExceptionHandler.class)        // bring your @ControllerAdvice into the slice
class UserControllerMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private JpaUserDetailsServiceCustom  jpaUserDetailsServiceCustom;

    @Autowired
    private ObjectMapper objectMapper;

    // ---------- GET /users (paged) ----------

    @Test
    void getUsers_returnsPagedUsersAndPaginationHeaders() throws Exception {
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();

        UserResponseDTO u1 = new UserResponseDTO();
        u1.setId(id1);
        u1.setEmail("alice@example.com");

        UserResponseDTO u2 = new UserResponseDTO();
        u2.setId(id2);
        u2.setEmail("bob@example.com");

        List<UserResponseDTO> content = List.of(u1, u2);

        PageRequest pageRequest = PageRequest.of(1, 5, Sort.by(Sort.Direction.DESC, "createdAt"));
        long totalElements = 40L;
        Page<UserResponseDTO> page = new PageImpl<>(content, pageRequest, totalElements);

        when(userService.getUsers(any(Pageable.class))).thenReturn(page);

        mockMvc.perform(get("/users")
                        .param("page", "1")
                        .param("size", "5"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", String.valueOf(totalElements)))
                .andExpect(header().string("X-Total-Pages", "8"))
                .andExpect(header().string("X-Page-Number", "1"))
                .andExpect(header().string("X-Page-Size", "5"))
                .andExpect(jsonPath("$[0].id").value(id1.toString()))
                .andExpect(jsonPath("$[0].email").value("alice@example.com"))
                .andExpect(jsonPath("$[1].id").value(id2.toString()))
                .andExpect(jsonPath("$[1].email").value("bob@example.com"));

        verify(userService).getUsers(any(Pageable.class));
    }

    // ---------- GET /users/{id} ----------

    @Test
    void getUser_returnsUserById() throws Exception {
        UUID id = UUID.randomUUID();

        UserResponseDTO user = new UserResponseDTO();
        user.setId(id);
        user.setEmail("alice@example.com");

        when(userService.getUserById(id)).thenReturn(user);

        mockMvc.perform(get("/users/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.email").value("alice@example.com"));

        verify(userService).getUserById(id);
    }

    @Test
    void getUser_whenNotFound_returnsBadRequestWithErrorBody() throws Exception {
        UUID id = UUID.randomUUID();

        when(userService.getUserById(id))
                .thenThrow(new UserNotFoundException("User %s not found".formatted(id)));

        mockMvc.perform(get("/users/{id}", id))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.user").value("User not found"));
    }

    // ---------- POST /users/signup ----------

    @Test
    void register_createsUserAndReturnsLocationHeader() throws Exception {
        UUID id = UUID.randomUUID();

        UserResponseDTO saved = new UserResponseDTO();
        saved.setId(id);
        saved.setEmail("alice@example.com");

        when(userService.addUser(any(UserRequestDTO.class))).thenReturn(saved);

        Map<String, Object> requestBody = Map.of(
                "email", "alice@example.com",
                "password", "StrongPassword123!"
        );

        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "http://localhost/users/signup/" + id));

        verify(userService).addUser(any(UserRequestDTO.class));
    }

    @Test
    void register_whenEmailAlreadyExists_returnsBadRequestWithErrorBody() throws Exception {
        when(userService.addUser(any(UserRequestDTO.class)))
                .thenThrow(new EmailAlreadyExistsException("Email already exists"));

        Map<String, Object> requestBody = Map.of(
                "email", "existing@example.com",
                "password", "StrongPassword123!"
        );

        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email already exists"));
    }

    @Test
    void register_withInvalidBody_returnsBadRequest() throws Exception {
        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // ---------- POST /users/login ----------
    @Test
    void login_withValidCredentials_returnsUserDtoAndJwtToken() throws Exception {
        UUID id = UUID.randomUUID();

        // principal returned by AuthenticationManager
        UserPrincipal principal = mock(UserPrincipal.class);
        when(principal.getId()).thenReturn(id);
        when(principal.getEmail()).thenReturn("login@example.com");
        when(principal.getAuthorities()).thenReturn(Collections.emptyList());

        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal,
                null,
                principal.getAuthorities()
        );

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(auth);

        UserResponseDTO dto = new UserResponseDTO();
        dto.setId(id);
        dto.setEmail("login@example.com");
        when(userService.getUserById(id)).thenReturn(dto);

        String jwt = "dummy-jwt-token";
        when(jwtService.generateToken(principal)).thenReturn(jwt);

        Map<String, Object> body = Map.of(
                "email", "login@example.com",
                "password", "secret"
        );

        mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value(jwt))
                .andExpect(jsonPath("$.user.id").value(id.toString()))
                .andExpect(jsonPath("$.user.email").value("login@example.com"));
    }

    @Test
    void login_withBadCredentials_returns401_andErrorBody() throws Exception {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        Map<String, Object> body = Map.of(
                "email", "wrong@example.com",
                "password", "wrong"
        );

        mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.auth").value("invalid email or password"));
    }


    // ---------- PATCH /users/{id} ----------
    @Test
    void updateUser_updatesAndReturnsUser() throws Exception {
        UUID id = UUID.randomUUID();

        UserResponseDTO updated = new UserResponseDTO();
        updated.setId(id);
        updated.setEmail("alice@example.com"); // email stays same in DTO

        when(userService.updateUser(eq(id), any(UserPatchDTO.class))).thenReturn(updated);

        Map<String, Object> patchBody = Map.of(
                "name", "New Name"
        );

        mockMvc.perform(patch("/users/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(patchBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.email").value("alice@example.com"));

        verify(userService).updateUser(eq(id), any(UserPatchDTO.class));
    }

    // ---------- PATCH /users/{id}/email ----------
    @WithMockUser(username = "user@example.com", roles = {"USER"})
    @Test
    void changeEmail_withValidBody_callsService_andReturnsNoContent() throws Exception {
        UUID id = UUID.randomUUID();

        String body = """
        {
          "newEmail": "new.email@example.com",
          "currentPassword": "CurrentPass123!"
        }
        """;

        mockMvc.perform(patch("/users/{id}/email", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNoContent());

        verify(userService).changeEmail(eq(id), any(EmailChangeDTO.class));
    }

    @WithMockUser(username = "user@example.com", roles = {"USER"})
    @Test
    void changeEmail_withMissingNewEmail_returnsBadRequest() throws Exception {
        UUID id = UUID.randomUUID();

        String body = """
        {
          "currentPassword": "CurrentPass123!"
        }{
          "currentPassword": "CurrentPass123!"
        }
        """;

        mockMvc.perform(patch("/users/{id}/email", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.newEmail").exists());

        verifyNoInteractions(userService);
    }

    @WithMockUser(username = "user@example.com", roles = {"USER"})
    @Test
    void changeEmail_withEmptyBody_returnsBadRequest() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(patch("/users/{id}/email", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))          // empty body
                .andExpect(status().isBadRequest());

        verifyNoInteractions(userService);
    }

    // ---------- PATCH /users/{id}/password ----------
    @Test
    void changePassword_whenWrongPassword_returnsBadRequestWithErrorBody() throws Exception {
        UUID id = UUID.randomUUID();

        doThrow(new WrongPasswordException("Old password does not match"))
                .when(userService).changePassword(eq(id), any(PasswordChangeDTO.class));

        Map<String, Object> body = Map.of(
                "oldPassword", "OldPassword123!",   // valid per your constraints
                "newPassword", "NewPassword123!"    // also valid
        );

        mockMvc.perform(patch("/users/{id}/password", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Credentials are wrong"));

        // optional but nice:
        verify(userService).changePassword(eq(id), any(PasswordChangeDTO.class));
    }


    @Test
    void changePassword_whenTooManyAttempts_returns429() throws Exception {
        UUID id = UUID.randomUUID();

        doThrow(new TooManyPasswordChangeAttemptsException("Too many failed attempts"))
                .when(userService).changePassword(eq(id), any(PasswordChangeDTO.class));

        Map<String, Object> body = Map.of(
                "oldPassword", "OldPassword123!",   // long & complex enough for @Size/@Pattern
                "newPassword", "NewPassword123!"    // same here
        );

        mockMvc.perform(patch("/users/{id}/password", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.password")
                        .value("Too many failed attempts. Please try again later."));

        // optional: prove service was actually called
        verify(userService).changePassword(eq(id), any(PasswordChangeDTO.class));
    }

    @Test
    void changePassword_withTooShortPassword_triggersValidationAndReturns400() throws Exception {
        UUID id = UUID.randomUUID();

        Map<String, Object> body = Map.of(
                "oldPassword", "",
                "newPassword", "short"
        );

        mockMvc.perform(patch("/users/{id}/password", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verify(userService, never()).changePassword(any(), any());
    }


    // ---------- PATCH /users/{id}/roles ----------
    @Test
    void updateUserRoles_whenRolesInvalid_returnsBadRequestWithErrorBody() throws Exception {
        UUID id = UUID.randomUUID();

        when(userService.updateUserRoles(eq(id), any(UserRolesUpdateDTO.class)))
                .thenThrow(new RoleNotFoundException("Role not found"));

        Map<String, Object> body = Map.of(
                "roles", List.of("NON_EXISTENT")
        );

        mockMvc.perform(patch("/users/{id}/roles", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.role").value("Role not found"));
    }

    @Test
    void updateUser_whenAccessDenied_returnsForbiddenWithProperMessage() throws Exception {
        UUID id = UUID.randomUUID();

        when(userService.updateUser(eq(id), any(UserPatchDTO.class)))
                .thenThrow(new AccessDeniedException("Only admin"));

        Map<String, Object> patchBody = Map.of(
                "name", "New Name"
        );

        mockMvc.perform(patch("/users/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(patchBody)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));
    }

    @Test
    void updateUser_whenPatchBodyIsNull_triggersBadRequestWithErrorBody() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(patch("/users/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))  // or "" – both will trigger HttpMessageNotReadableException
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.request").value("empty request body"));
    }

    // ---------- DELETE /users/{id} ----------

    @Test
    void deleteUser_deletesAndReturnsNoContent() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(delete("/users/{id}", id))
                .andExpect(status().isNoContent());

        verify(userService).deleteUser(id);
    }

    @Test
    void deleteUser_whenAccessDenied_returnsForbiddenWithProperMessage() throws Exception {
        UUID id = UUID.randomUUID();

        doThrow(new AccessDeniedException("Only admin"))
                .when(userService).deleteUser(id);

        mockMvc.perform(delete("/users/{id}", id))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.user").value("Insufficient privileges"));
    }
}
