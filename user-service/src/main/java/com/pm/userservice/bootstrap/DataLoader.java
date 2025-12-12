package com.pm.userservice.bootstrap;

import com.pm.userservice.domain.auth.Role;
import com.pm.userservice.repository.auth.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    @Autowired
    private RoleRepository roleRepository;

    @Transactional
    @Override
    public void run(String... args) {
        log.info(">>> DataLoader started");

        seedRole("ADMIN");
        seedRole("USER");

        log.info(">>> DataLoader finished");
    }

    private void seedRole(String code) {
        if (!roleRepository.existsByCode(code)) {
            log.info("Seeding role: {}", code);
            Role role = new Role();
            role.setCode(code);
            roleRepository.save(role);
        } else {
            log.info("Role {} already exists, skipping seeding", code);
        }
    }
}
