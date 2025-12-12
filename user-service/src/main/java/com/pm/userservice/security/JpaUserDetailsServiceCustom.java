package com.pm.userservice.security;

import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.repository.user.UserProfileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static com.pm.userservice.logging.LoggingUtils.maskEmail;

@Service
public class JpaUserDetailsServiceCustom implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(JpaUserDetailsServiceCustom.class);

    private final UserProfileRepository userProfileRepository;

    public JpaUserDetailsServiceCustom(UserProfileRepository userProfileRepository) {
        this.userProfileRepository = userProfileRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user for authentication username={}", maskEmail(username));

        UserProfile user = userProfileRepository.findByEmail(username)
                .orElseThrow(() -> {
                    log.warn("User not found during authentication username={}", maskEmail(username));
                    return new UsernameNotFoundException("User not found");
                });

        log.debug("User loaded for authentication userId={} email={}",
                user.getId(), maskEmail(user.getEmail()));

        return new UserPrincipal(user);
    }
}

