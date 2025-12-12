package com.pm.userservice.exception;

// Utility (e.g., ExceptionUtils.java)
import org.springframework.dao.DataIntegrityViolationException;
import org.hibernate.exception.ConstraintViolationException;

import java.sql.SQLException;
import java.util.Set;

public final class ExceptionUtils {

    // Put your actual constraint names here (DB-specific!)
    // e.g. for Postgres default naming: "<table>_<column>_key"
    private static final Set<String> EMAIL_UNIQUE_CONSTRAINT_NAMES = Set.of(
            "users_email_key",         // Postgres default if table "users" has unique (email)
            "uk_user_lower_email",     // your custom name if you created a functional unique index
            "uk_user_email"            // example Hibernate @UniqueConstraint name
    );

    private ExceptionUtils() {}

    public static boolean isEmailUniqueViolation(Throwable ex) {
        Throwable root = getRootCause(ex);

        // 1) Hibernate wrapper
        if (root instanceof ConstraintViolationException hce) {
            String constraintName = hce.getConstraintName();
            if (constraintName != null && isEmailConstraintName(constraintName)) return true;

            // Also check SQLState in case name is null
            return isDuplicateSqlState(hce.getSQLException());
        }

        // 2) Spring wraps vendor SQLException directly sometimes
        if (root instanceof SQLException sqlEx) {
            // Vendor-specific checks
            if (isDuplicateSqlState(sqlEx)) return true;          // Postgres (23505) and generic
        }

        return false;
    }

    private static boolean isEmailConstraintName(String name) {
        String n = name.toLowerCase();
        return EMAIL_UNIQUE_CONSTRAINT_NAMES.stream()
                .map(String::toLowerCase)
                .anyMatch(n::equals);
    }

    private static boolean isDuplicateSqlState(SQLException e) {
        // Postgres: 23505 = unique_violation
        // Some drivers keep SQLState up the cause chain
        for (SQLException cur = e; cur != null; cur = cur.getNextException()) {
            String state = cur.getSQLState();
            if ("23505".equals(state)) return true; // PostgreSQL
        }
        return false;
    }

    private static Throwable getRootCause(Throwable t) {
        Throwable result = t;
        while (result.getCause() != null && result.getCause() != result) {
            result = result.getCause();
        }
        return result;
    }
}

