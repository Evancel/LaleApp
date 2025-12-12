package com.pm.userservice.mail;

public interface EmailSender {
    void sendEmailVerification(String to, String verificationLink);
}
