package com.pm.userservice.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.pm.userservice.logging.LoggingUtils.*;

@Component
public class CorrelationIdFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String headerValue = request.getHeader(CORRELATION_ID_HEADER);
            String correlationId = (headerValue == null || headerValue.isBlank())
                    ? ensureCorrelationId()
                    : headerValue;

            putCorrelationId(correlationId);
            response.setHeader(CORRELATION_ID_HEADER, correlationId);

            filterChain.doFilter(request, response);
        } finally {
            clearCorrelationId();
        }
    }
}
