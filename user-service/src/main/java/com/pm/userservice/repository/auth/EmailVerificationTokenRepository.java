package com.pm.userservice.repository.auth;

import com.pm.userservice.domain.auth.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {
    Optional<EmailVerificationToken> findByToken(String token);
    @Modifying
    @Query("delete from EmailVerificationToken t where t.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);

}
