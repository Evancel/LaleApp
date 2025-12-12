package com.pm.userservice.config;

import com.pm.userservice.security.JpaUserDetailsServiceCustom;
import com.pm.userservice.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authProvider(JpaUserDetailsServiceCustom userDetailsServiceCustom,
                                                  PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsServiceCustom);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   DaoAuthenticationProvider provider,
                                                   JwtAuthenticationFilter jwtFilter) throws Exception {
        http.authenticationProvider(provider);
        http
                .httpBasic(Customizer.withDefaults())     //If you don’t want Basic Auth at all, you can even remove httpBasic() in prod later.
                .csrf(csrf -> csrf.disable()) // For Postman
                .headers(headers ->
                        headers.frameOptions(frame -> frame.disable())) // For the H2 console// for POST requests via Postman
                .sessionManagement(sessions
                        -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // no session
                .authorizeHttpRequests(auth -> auth
                        // swagger & api docs
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()
                        // public endpoints
                        .requestMatchers(HttpMethod.POST, "/users/signup").permitAll()
                        .requestMatchers(HttpMethod.POST, "/users/login").permitAll()
                        // everything else secured
                        .requestMatchers("/users/**").authenticated()
                        .anyRequest().permitAll())
//                .formLogin(login -> login.loginPage("/login").permitAll())
//                .logout(l -> l.permitAll())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request,
                                                   response,
                                                   authException) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json");
                            response.setCharacterEncoding("UTF-8");
                            response.getWriter().write("""
                                        {"auth":"invalid or missing credentials"}
                                    """);
                            ;
                        })
                        .accessDeniedHandler((request,
                                              response,
                                              accessDeniedException) -> {
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType("application/json");
                            response.setCharacterEncoding("UTF-8");
                            response.getWriter().write("""
                                        {"user":"Insufficient privileges"}
                                    """);
                        }))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
