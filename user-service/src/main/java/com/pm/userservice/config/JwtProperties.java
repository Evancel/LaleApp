package com.pm.userservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /**
     * HS256 secret, base64 or plain. Inject from env: JWT_SECRET
     */
    private String secret;

    /**
     * Token lifetime in milliseconds, e.g. 15 * 60 * 1000 = 15m
     */
    private long expirationMs = 15 * 60 * 1000;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }
}

