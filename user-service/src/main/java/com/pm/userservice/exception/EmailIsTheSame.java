package com.pm.userservice.exception;

public class EmailIsTheSame extends RuntimeException {
    public EmailIsTheSame(String message) {
        super(message);
    }
}
