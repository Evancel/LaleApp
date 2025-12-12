package com.pm.userservice.security;

import com.pm.userservice.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final JwtProperties props;

    public JwtService(JwtProperties props) {
        this.props = props;
    }

    private SecretKey getSigningKey() {
        String secret = props.getSecret();
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);

        if (keyBytes.length < 32) { // 256 bits for HS256
            throw new IllegalStateException("JWT secret must be at least 32 bytes long. secret = " + secret);
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserPrincipal principal) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(props.getExpirationMs());

        List<String> roles = principal.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .toList();

        return Jwts.builder()
                .subject(principal.getId().toString())        // sub = userId
                .claim("email", principal.getEmail())
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractSubject(String token) {
        Claims claims = parseToken(token);
        return claims.getSubject(); // userId as string
    }

    public String extractEmail(String token) {
        Claims claims = parseToken(token);
        return claims.get("email", String.class);
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = parseToken(token);
            Date exp = claims.getExpiration();
            return exp == null || exp.toInstant().isAfter(Instant.now());
        } catch (Exception ex) {
            // invalid signature, malformed, expired, etc.
            return false;
        }
    }

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}