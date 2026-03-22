package com.dvelupmint.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger loggerInstance = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String requestUri = request.getMethod() + " " + request.getRequestURI();

        loggerInstance.info("JWT Filter - Processing request: {}", requestUri);
        loggerInstance.info("JWT Filter - Authorization header: {}", authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            loggerInstance.info("JWT Filter - No valid Bearer token found → continuing as anonymous");
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        loggerInstance.info("JWT Filter - Token received (first 30 chars): {}",
                token.length() > 30 ? token.substring(0, 30) + "..." : token);

        try {
            // Step 1: Validate token first
            if (!jwtUtil.validateToken(token)) {
                loggerInstance.warn("JWT Filter - validateToken returned false for token");
                filterChain.doFilter(request, response);
                return;
            }

            // Step 2: Extract email/subject
            String email = jwtUtil.extractEmail(token);
            loggerInstance.info("JWT Filter - Extracted email/subject: {}", email);

            if (email == null) {
                loggerInstance.warn("JWT Filter - Email/subject is null after extraction");
                filterChain.doFilter(request, response);
                return;
            }

            // Step 3: Check if authentication is already set
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                loggerInstance.info("JWT Filter - No existing authentication → loading user");

                // Step 4: Load user details
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                loggerInstance.info("JWT Filter - User loaded successfully: username={}, authorities={}",
                        userDetails.getUsername(), userDetails.getAuthorities());

                // Step 5: Create authentication token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities() // ← use loaded authorities
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

                loggerInstance.info("JWT Filter - Authentication SET SUCCESSFULLY for user: {}", email);
            } else {
                loggerInstance.info("JWT Filter - Authentication already present → skipping");
            }

        } catch (Exception e) {
            loggerInstance.error("JWT Filter - Authentication failed for request {}: {}", requestUri, e.getMessage(), e);
        }

        filterChain.doFilter(request, response);
    }
}