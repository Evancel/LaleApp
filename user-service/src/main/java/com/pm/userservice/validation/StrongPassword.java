package com.pm.userservice.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

    String message() default "Password is too weak";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    // configurable rules
    int minLength() default 8;

    boolean requireUppercase() default true;

    boolean requireLowercase() default true;

    boolean requireDigit() default true;

    boolean requireSpecial() default true;
}

