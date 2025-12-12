package com.pm.userservice.config;


import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
@OpenAPIDefinition(
        info = @Info(
                title = "LaleApp User Service API",
                version = "v1",
                description = "REST API for user accounts, auth, roles and email verification"
        ),
        security = {
                @SecurityRequirement(name = "bearerAuth")   // global: all endpoints require JWT
        }
)
public class OpenApiConfig {
    // no OpenAPI bean needed, springdoc generates it for you
}

