package com.pm.userservice.advice;

import com.pm.userservice.exception.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<Map<String, String>> handleDisabledUser(DisabledException ex) {
        log.warn("Email not verified: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("user", "Email not verified");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errors);
    }

    @ExceptionHandler(InvalidVerificationTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidVerificationToken(InvalidVerificationTokenException ex) {
        log.warn("Invalid verification token: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("token", "Invalid or expired verification link");
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleValidationException(EmailAlreadyExistsException ex) {
        log.warn("Email already exists: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("email", "Email already exists");
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFoundException(UserNotFoundException ex) {
        log.warn("User not found: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("user", "User not found");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errors);
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleRoleNotFoundException(RoleNotFoundException ex) {
        log.warn("Role not found: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("role", "Role not found");
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(WrongPasswordException.class)
    public ResponseEntity<Map<String, String>> handleWrongPasswordException(WrongPasswordException ex) {
        log.warn("Wrong password provided: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("password", "Credentials are wrong");
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(TooManyPasswordChangeAttemptsException.class)
    public ResponseEntity<Map<String, String>> handleTooManyPasswordChangeAttemptsException(
            TooManyPasswordChangeAttemptsException ex
    ) {
        log.warn("Password change temporarily locked due to repeated failures: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("password", "Too many failed attempts. Please try again later.");
        return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .body(errors);
    }

    @ExceptionHandler({AccessDeniedException.class, AuthorizationDeniedException.class})
    public ResponseEntity<Map<String, String>> handleAccessDeniedException(RuntimeException ex) {
        log.warn("Access denied: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("user", "Insufficient privileges");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errors);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        log.warn("Invalid request body: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("request", "empty request body");
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        log.warn("Invalid request body: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(err ->
                errors.put(err.getField(), err.getDefaultMessage())
        );
        return ResponseEntity.badRequest().body(errors);
    }

    //wrong email
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(BadCredentialsException ex) {
        log.warn("Bad credentials during authentication: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        errors.put("auth", "invalid email or password");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errors);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, String>> handleNoResource(NoResourceFoundException ex,
                                                     HttpServletRequest request) {
        log.debug("No resource for URI: {}", request.getRequestURI());

        Map<String, String> errors = new HashMap<>();
        errors.put("error", "Resource not found");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errors);
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleUnexpected(Exception ex) {
        log.error("Unexpected error", ex);

        Map<String, String> errors = new HashMap<>();
        errors.put("error", "Internal server error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errors);
    }
}
