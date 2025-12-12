package com.pm.userservice.controller;

import com.pm.userservice.dto.auth.LoginRequestDTO;
import com.pm.userservice.dto.auth.LoginResponseDTO;
import com.pm.userservice.dto.user.*;
import com.pm.userservice.security.JwtService;
import com.pm.userservice.security.UserPrincipal;
import com.pm.userservice.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.pm.userservice.logging.LoggingUtils.maskEmail;

@Tag(
        name = "Users",
        description = """
                Operations on user profiles.

                Authentication flow in Swagger UI:
                1. Call POST /users/login with valid credentials.
                2. Copy the JWT token from the response.
                3. Click the "Authorize" button and choose 'bearerAuth'.
                4. Paste the token and confirm.
                5. Now you can call protected /users endpoints.
                """
)
@RestController
@RequestMapping("/users")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtService jwtService;

    public UserController(AuthenticationManager authenticationManager,
                          UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    // ============================================================
    // GET /users/me
    // ============================================================
    @Operation(
            summary = "Get current authenticated user",
            description = """
                    Returns the profile of the currently authenticated user (from JWT).

                    Requires a valid JWT Bearer token:
                    - First call POST /users/login with valid credentials.
                    - Copy the token from the response.
                    - In Swagger UI, click "Authorize", choose 'bearerAuth', paste the token and execute this request.
                    """,
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Current user profile",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized (missing or invalid JWT)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponseDTO> getCurrentUser(
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        UUID id = principal.getId();
        log.info("Get current user userId={}", id);

        UserResponseDTO userResponseDTO = userService.getUserById(id);
        return ResponseEntity.ok(userResponseDTO);
    }

    // ============================================================
    // GET /users (admin only)
    // ============================================================

    @Operation(
            summary = "List users (admin only)",
            description = """
                    Returns a paginated list of users.

                    Requires:
                    - A valid JWT Bearer token.
                    - Role ADMIN.
                    """,
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Users retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = UserResponseDTO.class))
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized (no or invalid credentials)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (not ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponseDTO>> getUsers(
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable
    ) {
        log.info("Admin listing users page={} size={} sort={}",
                pageable.getPageNumber(), pageable.getPageSize(), pageable.getSort());

        Page<UserResponseDTO> page = userService.getUsers(pageable);

        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Total-Count", String.valueOf(page.getTotalElements()));
        headers.add("X-Total-Pages", String.valueOf(page.getTotalPages()));
        headers.add("X-Page-Number", String.valueOf(pageable.getPageNumber()));
        headers.add("X-Page-Size", String.valueOf(pageable.getPageSize()));

        return new ResponseEntity<>(page.getContent(), headers, HttpStatus.OK);
    }

    // ============================================================
    // GET /users/{id}
    // ============================================================

    @Operation(
            summary = "Get user by ID",
            description = """
                Returns a user profile. Accessible by the user themself or an ADMIN.

                To test in Swagger UI:
                1. Call POST /users/login with valid credentials.
                2. Copy the JWT token from the response.
                3. Click the "Authorize" button and choose 'bearerAuth'.
                4. Paste the token and execute this request.
                """,
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "User found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (neither owner nor ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @GetMapping("/{id}")
    @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    public ResponseEntity<UserResponseDTO> getUser(@PathVariable UUID id,
                                                   @AuthenticationPrincipal UserPrincipal principal) {
        log.info("Get user userId={} requestedBy={}", id,
                principal != null ? principal.getId() : null);

        UserResponseDTO userResponseDTO = userService.getUserById(id);
        return ResponseEntity.ok(userResponseDTO);
    }

    // ============================================================
    // POST /users/signup
    // ============================================================

    @Operation(
            summary = "User signup",
            description = """
                    Registers a new user, stores it as disabled and sends a verification email.

                    Public endpoint (no JWT required).
                    """,
            security = {}   // explicitly public despite global bearerAuth
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "User created, verification email sent; Location header contains resource URL"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error or email already exists",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@Valid @RequestBody UserRequestDTO userRequestDTO) {
        log.info("Signup requested email={}", maskEmail(userRequestDTO.getEmail()));

        UserResponseDTO savedUserProfile = userService.addUser(userRequestDTO);

        log.info("Signup completed userId={} email={}",
                savedUserProfile.getId(), maskEmail(savedUserProfile.getEmail()));

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(savedUserProfile.getId())
                .toUri();
        return ResponseEntity.created(location).build();
    }

    // ============================================================
    // POST /users/login
    // ============================================================

    @Operation(
            summary = "User login",
            description = """
                    Authenticates user by email and password and returns a JWT token with user info.

                    Public endpoint (no JWT required). Use the returned JWT in:
                    - Swagger UI: click "Authorize" → 'bearerAuth' → paste token.
                    - HTTP clients: send header Authorization: Bearer <token>.
                    """,
            security = {}   // public
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Login successful, JWT token and user info returned",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request body (validation errors)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid email or password",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Email not verified (user disabled)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@Valid @RequestBody LoginRequestDTO request) {
        log.info("Login attempt email={}", maskEmail(request.getEmail()));

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(request.getEmail().toLowerCase(), request.getPassword());

        Authentication authentication = authenticationManager.authenticate(token);

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        UUID userId = principal.getId();

        log.info("Login success userId={} email={}", userId, maskEmail(principal.getEmail()));

        UserResponseDTO dto = userService.getUserById(userId);
        String jwt = jwtService.generateToken(principal);
        return ResponseEntity.ok(new LoginResponseDTO(jwt, dto));
    }

    // ============================================================
    // PATCH /users/{id}
    // ============================================================

    @Operation(
            summary = "Update user profile",
            description = "Partially updates user profile fields. Accessible by the user themself or an ADMIN.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "User updated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error in patch data",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (neither owner nor ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @PatchMapping("/{id}")
    @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    public ResponseEntity<UserResponseDTO> updateUserProfile(@PathVariable UUID id,
                                                             @RequestBody UserPatchDTO patch,
                                                             @AuthenticationPrincipal UserPrincipal principal) {
        log.info("Profile update requested userId={} requestedBy={}",
                id, principal != null ? principal.getId() : null);

        UserResponseDTO userResponseDTO = userService.updateUser(id, patch);
        return ResponseEntity.ok(userResponseDTO);
    }

    // ============================================================
    // PATCH /users/{id}/email
    // ============================================================

    @Operation(
            summary = "Change user email",
            description = "Changes the user's email after verifying the current password. " +
                    "User is typically disabled until the new email is verified.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Email change accepted"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error or wrong current password",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (neither owner nor ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @PatchMapping("/{id}/email")
    @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    public ResponseEntity<Void> changeEmail(@PathVariable UUID id,
                                            @Valid @RequestBody EmailChangeDTO dto,
                                            @AuthenticationPrincipal UserPrincipal principal) {
        log.info("Email change requested userId={} requestedBy={} newEmail={}",
                id,
                principal != null ? principal.getId() : null,
                maskEmail(dto.newEmail()));

        userService.changeEmail(id, dto);
        return ResponseEntity.noContent().build();
    }

    // ============================================================
    // PATCH /users/{id}/password
    // ============================================================

    @Operation(
            summary = "Change user password",
            description = "Changes the user's password after verifying the old password. " +
                    "Includes protection against too many failed attempts.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Password changed successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error or wrong old password",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (neither owner nor ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "429",
                    description = "Too many failed password change attempts",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @PatchMapping("/{id}/password")
    @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    public ResponseEntity<Void> changePassword(@PathVariable UUID id,
                                               @Valid @RequestBody PasswordChangeDTO dto,
                                               @AuthenticationPrincipal UserPrincipal principal) {
        log.info("Password change requested userId={} requestedBy={}",
                id,
                principal != null ? principal.getId() : null);

        userService.changePassword(id, dto);
        return ResponseEntity.noContent().build();
    }

    // ============================================================
    // PATCH /users/{id}/roles
    // ============================================================

    @Operation(
            summary = "Update user roles",
            description = "Updates roles for a given user. Only ADMIN is allowed.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Roles updated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error or role not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (not ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @PatchMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponseDTO> updateUserRoles(@PathVariable UUID id,
                                                           @RequestBody UserRolesUpdateDTO dto,
                                                           @AuthenticationPrincipal UserPrincipal principal) {
        log.info("Role update requested for userId={} byAdmin={}",
                id,
                principal != null ? principal.getId() : null);

        UserResponseDTO userResponseDTO = userService.updateUserRoles(id, dto);
        return ResponseEntity.ok(userResponseDTO);
    }

    // ============================================================
    // DELETE /users/{id}
    // ============================================================

    @Operation(
            summary = "Delete user",
            description = "Deletes a user. Accessible by the user themself or an ADMIN.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "User deleted successfully"
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Insufficient privileges (neither owner nor ADMIN)",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(schema = @Schema(implementation = Map.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(implementation = Map.class))
            )
    })
    @DeleteMapping("/{id}")
    @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id,
                                           @AuthenticationPrincipal UserPrincipal principal) {
        log.info("User delete requested userId={} requestedBy={}",
                id,
                principal != null ? principal.getId() : null);

        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
