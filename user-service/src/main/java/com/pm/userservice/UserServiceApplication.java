package com.pm.userservice;

import com.pm.userservice.config.JwtProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Autowired;

@SpringBootApplication
@ConfigurationPropertiesScan(basePackageClasses = JwtProperties.class)
public class UserServiceApplication {

    private static final Logger log = LoggerFactory.getLogger(UserServiceApplication.class);

    private final Environment env;

    @Autowired
    public UserServiceApplication(Environment env) {
        this.env = env;
    }

    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logStartup() {
        String profiles = String.join(",", env.getActiveProfiles());
        log.info("UserService started. Active profiles={}", profiles);

        log.info("Database url={}", env.getProperty("spring.datasource.url"));
        log.info("Mail host={}", env.getProperty("spring.mail.host"));
    }
}

