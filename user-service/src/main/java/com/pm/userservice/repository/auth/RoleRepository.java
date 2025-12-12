package com.pm.userservice.repository.auth;

import com.pm.userservice.domain.auth.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByCode(String code);
    boolean existsByCode(String code);
}
