package com.dvelupmint.app.controller;

import com.dvelupmint.app.model.User;
import com.dvelupmint.app.payload.RegisterRequest;
import com.dvelupmint.app.repository.RefreshTokenRepository;
import com.dvelupmint.app.repository.UserRepository;
import com.dvelupmint.app.security.JwtUtil;
import com.dvelupmint.app.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    // Constructor-based injection of dependencies (repository, encoder, and JWT)
    @Autowired
    public AuthController(UserRepository userRepo, PasswordEncoder encoder, JwtUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.userRepo = userRepo;
        this.passwordEncoder = encoder;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userRepo.findByEmail(request.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body(
                    Map.of("error", "EMAIL_IN_USE", "message", "Email already in use"));
        }

        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already in use");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());

        userRepo.save(user);
        return ResponseEntity.ok("User registered");

    }

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String identifier = credentials.get("identifier");
        String password = credentials.get("password");

        // Check if identifier is an email (crude check)
        boolean isEmail = identifier.contains("@");

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            isEmail ? identifier
                                    : userRepo.findByUsername(identifier)
                                    .orElseThrow(() -> new RuntimeException("User not found"))
                                    .getEmail(), // Convert username to email for auth
                            password));

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User dbUser = userRepo.findByEmail(userDetails.getUsername()).orElseThrow();

            Map<String, Object> claims = new HashMap<>();
            claims.put("role", dbUser.getRole());
            claims.put("username", dbUser.getUsername());
            String token = jwtUtil.generateTokenWithClaims(claims, dbUser.getEmail());
            String refreshToken = refreshTokenService.createRefreshToken(dbUser.getId()).getToken();

            return ResponseEntity.ok(Map.of("accessToken", token, "refreshToken", refreshToken));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> credentials) {
        String refreshToken = credentials.get("refreshToken");
        Map response;
        try {
            response = refreshTokenService.rotateToken(refreshToken);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid refreshToken");
        }
        return ResponseEntity.ok(response);
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logout(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            String email = authentication.getName();
            refreshTokenService.logoutAllUserSessions(email);
            return ResponseEntity.noContent().build(); 
        }
        return ResponseEntity.status(401).body("Not authenticated");
    }
}