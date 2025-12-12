package com.pm.userservice.controller;

import com.pm.userservice.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.pm.userservice.logging.LoggingUtils.maskToken;

@Tag(name = "Auth", description = "Authentication & email verification endpoints")
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @Operation(
            summary = "Verify email address",
            description = """
                    Verifies user email using a verification token sent by email.
                    
                    - On success: enables the user and marks token as used.
                    - On failure: returns a 400 with a generic `"token": "Invalid or expired verification link"` message.
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Email verified successfully (no content on success)"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or expired verification token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Map.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Map.class)
                    )
            )
    })
    @GetMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@RequestParam("token") String token) {
        log.info("Email verification requested token={}", maskToken(token));

        userService.verifyEmail(token);
        return ResponseEntity.noContent().build();
    }
}


