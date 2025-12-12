package com.pm.userservice.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    private int minLength;
    private boolean requireUppercase;
    private boolean requireLowercase;
    private boolean requireDigit;
    private boolean requireSpecial;

    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("\\d");
    private static final Pattern SPECIAL = Pattern.compile("[^A-Za-z0-9]");

    @Override
    public void initialize(StrongPassword annotation) {
        this.minLength = annotation.minLength();
        this.requireUppercase = annotation.requireUppercase();
        this.requireLowercase = annotation.requireLowercase();
        this.requireDigit = annotation.requireDigit();
        this.requireSpecial = annotation.requireSpecial();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        // Let @NotBlank/@NotNull handle null/empty if you use them.
        if (value == null || value.isBlank()) {
            return false;
        }

        if (value.length() < minLength) {
            return false;
        }
        if (requireUppercase && !UPPERCASE.matcher(value).find()) {
            return false;
        }
        if (requireLowercase && !LOWERCASE.matcher(value).find()) {
            return false;
        }
        if (requireDigit && !DIGIT.matcher(value).find()) {
            return false;
        }
        if (requireSpecial && !SPECIAL.matcher(value).find()) {
            return false;
        }

        return true;
    }
}

