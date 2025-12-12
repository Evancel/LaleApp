package com.pm.userservice.logging;

import org.slf4j.MDC;

import java.util.UUID;

public final class LoggingUtils {

    public static final String CORRELATION_ID_KEY = "correlationId";
    public static final String CORRELATION_ID_HEADER = "X-Request-Id";

    private LoggingUtils() {
        // utility class: no instances
    }

    // ============ Masking helpers ============

    public static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }
        String[] parts = email.split("@", 2);
        String local = parts[0];
        String domain = parts[1];

        if (local.length() <= 2) {
            return "***@" + domain;
        }
        return local.substring(0, 2) + "***@" + domain;
    }

    public static String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return token;
        }
        if (token.length() <= 6) {
            return "***";
        }
        return token.substring(0, 6) + "...";
    }

    // ============ Correlation ID helpers ============

    /**
     * Returns existing correlationId from MDC or generates a new one
     * and stores it in MDC.
     */
    public static String ensureCorrelationId() {
        String existing = MDC.get(CORRELATION_ID_KEY);
        if (existing != null && !existing.isBlank()) {
            return existing;
        }
        String generated = UUID.randomUUID().toString();
        MDC.put(CORRELATION_ID_KEY, generated);
        return generated;
    }

    public static void putCorrelationId(String correlationId) {
        if (correlationId != null && !correlationId.isBlank()) {
            MDC.put(CORRELATION_ID_KEY, correlationId);
        }
    }

    public static void clearCorrelationId() {
        MDC.remove(CORRELATION_ID_KEY);
    }
}
