package com.dvelupmint.app.config;

import com.dvelupmint.app.model.User;
import com.dvelupmint.app.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AdminInitializer {

    private static final Logger log = LoggerFactory.getLogger(AdminInitializer.class);

    private static final String ADMIN_EMAIL = "superadmin@email.com";
    private static final String ADMIN_USERNAME = "superadmin";

    @Value("${spring.datasource.AdminPassword}")
    private String adminPassword; // Removed the final attribute or the @Value don't work

    @Bean
    CommandLineRunner initAdmin(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            var optionalUser = userRepository.findByEmail(ADMIN_EMAIL);

            User admin;
            if (optionalUser.isEmpty()) {
                log.warn("Creating default admin user...");
                admin = new User();
                admin.setEmail(ADMIN_EMAIL);
                admin.setUsername(ADMIN_USERNAME);
                admin.setPassword(passwordEncoder.encode(adminPassword));
                admin.setRole("ADMIN");
            } else {
                admin = optionalUser.get();
                if (!"ADMIN".equals(admin.getRole())) {
                    log.warn("Repairing superadmin role → was {}, setting to ADMIN", admin.getRole());
                    admin.setRole("ADMIN");
                } else {
                    log.info("Superadmin already exists with correct role");
                    return;
                }
            }

            userRepository.save(admin);
            log.warn("SUPERADMIN ENSURED → login with: {} / {}", ADMIN_EMAIL, adminPassword);
        };
    }
}