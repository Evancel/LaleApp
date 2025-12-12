package com.pm.userservice.domain.user;

import com.pm.userservice.domain.auth.EmailVerificationToken;
import com.pm.userservice.domain.auth.Role;
import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.*;

@Table(
        name = "users",
        uniqueConstraints = @UniqueConstraint(name = "uk_user_lower_email", columnNames = {"email"})
)
@Entity
public class UserProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    private String name;

    private int passwordChangeFailedAttempts;

    private Instant lastPasswordChangeFailedAt;

    private boolean enabled = true;
    private Instant emailVerifiedAt;

    private boolean accountLocked = false;

    @Column(nullable = false, updatable = false)
    @CreationTimestamp   // from org.hibernate.annotations
    private Instant createdAt;


    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name="user_roles",
            joinColumns=@JoinColumn(name="user_id"),
            inverseJoinColumns=@JoinColumn(name="role_id"))
    private Set<Role> roles = new LinkedHashSet<>();

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getPasswordChangeFailedAttempts() {
        return passwordChangeFailedAttempts;
    }

    public void setPasswordChangeFailedAttempts(int passwordChangeFailedAttempts) {
        this.passwordChangeFailedAttempts = passwordChangeFailedAttempts;
    }

    public Instant getLastPasswordChangeFailedAt() {
        return lastPasswordChangeFailedAt;
    }

    public void setLastPasswordChangeFailedAt(Instant lastPasswordChangeFailedAt) {
        this.lastPasswordChangeFailedAt = lastPasswordChangeFailedAt;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getEmailVerifiedAt() {
        return emailVerifiedAt;
    }

    public void setEmailVerifiedAt(Instant emailVerifiedAt) {
        this.emailVerifiedAt = emailVerifiedAt;
    }

    public boolean isAccountLocked() {
        return accountLocked;
    }

    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        UserProfile that = (UserProfile) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }
}
