package com.pm.userservice.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile({"dev", "test"})
public class LoggingEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingEmailSender.class);

    @Override
    public void sendEmailVerification(String to, String verificationLink) {
        log.info("EMAIL VERIFICATION to={} link={}", to, verificationLink);
    }
}

