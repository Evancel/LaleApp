package com.pm.userservice.exception;

public class TooManyPasswordChangeAttemptsException extends RuntimeException {
    public TooManyPasswordChangeAttemptsException(String message) {
        super(message);
    }
}
