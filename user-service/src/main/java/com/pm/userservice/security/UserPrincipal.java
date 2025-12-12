package com.pm.userservice.security;

import com.pm.userservice.domain.user.UserProfile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class UserPrincipal implements UserDetails {
    private final UUID id;
    private final String email;
    private final String password;
    private final boolean enabled;
    private final boolean locked;
    private final Set<GrantedAuthority> authorities;

    public UserPrincipal(UserProfile userProfile) {
        this.id = userProfile.getId();
        this.email = userProfile.getEmail();
        this.password = userProfile.getPassword();
        this.enabled = userProfile.isEnabled();
        this.locked = userProfile.isAccountLocked();
        this.authorities = userProfile.getRoles().stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.getCode()))
                .collect(Collectors.toSet());
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
