package com.dvelupmint.app.controller;

import com.dvelupmint.app.model.User;
import com.dvelupmint.app.repository.UserRepository;
import com.dvelupmint.app.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private static final String ADMIN = "ADMIN";
    private static final String USER_NOT_FOUND = "User not found with ID";

    private static final List<String> PROTECTED_EMAILS = List.of(
            "superadmin@email.com",
            "founder@email.com");

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private JwtUtil jwtUtil;

    // Simple admin test endpoint
    @GetMapping("")
    public ResponseEntity<String> adminTest() {
        return ResponseEntity.ok("Welcome, Admin! You have secured access.");
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userRepo.findAll());
    }

    @PutMapping("/promote/{id}")
    public ResponseEntity<String> promoteUser(@PathVariable Long id) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(USER_NOT_FOUND + id));

        if (ADMIN.equals(user.getRole())) {
            return ResponseEntity.badRequest().body("User is already an admin.");
        }

        user.setRole(ADMIN);
        userRepo.save(user);

        return ResponseEntity.ok("User promoted to admin successfully.");
    }

    @PutMapping("/demote/{id}")
    public ResponseEntity<String> demoteUser(
            @PathVariable Long id,
            @RequestHeader("Authorization") String authHeader) {
        User targetUser = userRepo.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(USER_NOT_FOUND + id));

        String currentEmail = extractEmailFromHeader(authHeader);

        // Prevent self-demotion
        if (targetUser.getEmail().equals(currentEmail)) {
            return ResponseEntity.badRequest().body("❌ You cannot demote yourself.");
        }

        // Prevent demoting protected accounts
        if (PROTECTED_EMAILS.contains(targetUser.getEmail())) {
            return ResponseEntity.badRequest().body("❌ This account is protected from demotion.");
        }

        if (!ADMIN.equals(targetUser.getRole())) {
            return ResponseEntity.badRequest().body("User is not an admin.");
        }

        targetUser.setRole("USER");
        userRepo.save(targetUser);

        return ResponseEntity.ok("✅ User demoted to regular user.");
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<String> deleteUser(
            @PathVariable Long id,
            @RequestHeader("Authorization") String authHeader) {
        User targetUser = userRepo.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(USER_NOT_FOUND + id));

        String currentEmail = extractEmailFromHeader(authHeader);

        // Prevent self-deletion
        if (targetUser.getEmail().equals(currentEmail)) {
            return ResponseEntity.badRequest().body("❌ You cannot delete your own account.");
        }

        // Prevent deleting protected accounts
        if (PROTECTED_EMAILS.contains(targetUser.getEmail())) {
            return ResponseEntity.badRequest().body("❌ This account is protected from deletion.");
        }

        try {
            userRepo.deleteById(id);
            return ResponseEntity.ok("✅ User deleted successfully.");
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("❌ Error deleting user: " + e.getMessage());
        }
    }

    @DeleteMapping("/users/bulk")
    public ResponseEntity<String> bulkDeleteUsers(
            @RequestBody List<Long> userIds,
            @RequestHeader("Authorization") String authHeader) {
        String currentEmail = extractEmailFromHeader(authHeader);
        int deletedCount = 0;

        for (Long id : userIds) {
            User user = userRepo.findById(id).orElse(null);

            // Skip protected users and self
            if (user == null || user.getEmail().equals(currentEmail) ||
                    PROTECTED_EMAILS.contains(user.getEmail())) {
                continue;
            }

            try {
                userRepo.deleteById(id);
                deletedCount++;
            } catch (Exception ignored) {
                //ignored
            }
        }

        if (deletedCount == 0) {
            return ResponseEntity.badRequest().body("No eligible users were deleted.");
        }

        return ResponseEntity.ok("✅ " + deletedCount + " users deleted successfully.");
    }

    // Helper method – extract email from JWT
    private String extractEmailFromHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid or missing Authorization header");
        }
        String token = authHeader.replace("Bearer ", "");
        return jwtUtil.extractEmail(token);
    }
}