package com.pm.userservice.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import static com.pm.userservice.logging.LoggingUtils.maskEmail;

@Service
@Profile("prod")
public class SmtpEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);

    //TODO You can later switch to HTML emails with MimeMessageHelper, but this is enough to start.
    private final JavaMailSender mailSender;

    public SmtpEmailSender(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void sendEmailVerification(String to, String verificationLink) {
        String maskedTo = maskEmail(to);
        log.info("Sending verification email to={}", maskedTo);

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject("Please verify your email");
        msg.setText("""
                Hello,

                Please verify your email by clicking this link:

                %s

                If you did not request this, you can ignore this email.
                """.formatted(verificationLink));

        try {
            mailSender.send(msg);
            log.info("Verification email sent successfully to={}", maskedTo);
        } catch (MailException ex) {
            log.error("Failed to send verification email to={} reason={}", maskedTo, ex.getMessage(), ex);
            throw ex;
        }
    }
}