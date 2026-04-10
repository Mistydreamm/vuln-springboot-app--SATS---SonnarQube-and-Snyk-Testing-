package com.dvelupmint.app.service;

import com.dvelupmint.app.model.RefreshToken;
import com.dvelupmint.app.model.User;
import com.dvelupmint.app.repository.RefreshTokenRepository;
import com.dvelupmint.app.repository.UserRepository;
import com.dvelupmint.app.security.JwtUtil;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    @Value("${jwt.refreshExpirationMs}")
    private Long refreshExpirationMs;


    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository, JwtUtil jwtUtil) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    public RefreshToken createRefreshToken(Long userId) throws Exception {

        try {
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setCreatedAt(Instant.now());
            refreshToken.setToken(UUID.randomUUID().toString()); //todo : use SecureRandom instead of UUID
            refreshToken.setExpiryDate(LocalDateTime.now().plus(refreshExpirationMs, ChronoUnit.MILLIS));
            refreshToken.setUser(userRepository.findById(userId).get());

            refreshToken.setRevoked(false);
            refreshTokenRepository.save(refreshToken);
            return refreshToken;
        } catch (Exception e) {
            throw new NoSuchElementException(e);
        }
    }

    public Map<String, String> rotateToken(String token) throws Exception {

        if (refreshTokenRepository.findByToken(token).isPresent()) {
            RefreshToken refreshToken = refreshTokenRepository.findByToken(token).get();

            // Reuse attack Handling
            if (refreshToken.isRevoked()) {
                LOGGER.warn("Be careful, a reuse attack is running");
                refreshTokenRepository.revokeAllByUserId(
                        refreshToken.getUser().getId()
                );
                Exception SecurityException = new Exception("Danger : Reuse attack");
                throw SecurityException;
            }

            //Token expired
            else if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
                refreshToken.setRevoked(true);
                refreshTokenRepository.save(refreshToken);
                Exception ExpiredRefreshJwtException = new Exception("Expired JWT RefreshToken");
                throw ExpiredRefreshJwtException;
            }

            //Rotation
            else {
                refreshToken.setRevoked(true);
                RefreshToken newRefreshToken = createRefreshToken(refreshToken.getUser().getId());
                refreshToken.setReplacedByToken(newRefreshToken.getToken());
                refreshTokenRepository.save(refreshToken);

                User user = refreshToken.getUser();
                String role = user.getRole();

                Map<String, Object> claims = new HashMap<>();
                claims.put("role", role);

                String newToken = jwtUtil.generateTokenWithClaims(claims, user.getUsername());

                Map<String, String> response = new HashMap<>();
                response.put("accessToken", newToken);
                response.put("refreshToken", newRefreshToken.getToken());
                return response;
            }


            //Token not present in the DB
        } else {
            Exception InvalidTokenException = new Exception("Invalid token");
            throw InvalidTokenException;
        }
    }
    @Scheduled(fixedDelay = 10, timeUnit = TimeUnit.SECONDS) //
    @Transactional
    public void deleteExpiredTokens(){
        LocalDateTime now = LocalDateTime.now();
        LOGGER.trace("Deletion of the expired refresh tokens");

        refreshTokenRepository.deleteByExpiryDateBefore(now);
    }

    @Transactional
    public void logoutAllUserSessions(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        refreshTokenRepository.revokeAllByUserId(user.getId());
        LOGGER.info("User {} logged out: All refresh tokens revoked.", email);
    }

}