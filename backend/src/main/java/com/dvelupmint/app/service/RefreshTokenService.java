package com.dvelupmint.app.service;

import com.dvelupmint.app.model.RefreshToken;
import com.dvelupmint.app.model.User;
import com.dvelupmint.app.repository.RefreshTokenRepository;
import com.dvelupmint.app.repository.UserRepository;
import jakarta.persistence.Temporal;
import org.springframework.beans.factory.annotation.Value;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.TemporalUnit;
import java.util.UUID;

public class RefreshTokenService {

    /*
    @Service
public class RefreshTokenService {
    @Value("${jwt.refreshExpirationMs}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository repo, UserRepository userRepo) {
        this.refreshTokenRepository = repo;
        this.userRepository = userRepo;
    }

    public RefreshToken createRefreshToken(Long userId) {
        var token = new RefreshToken();
        token.setUser(userRepository.findById(userId).get());
        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        token.setToken(UUID.randomUUID().toString());
        return refreshTokenRepository.save(token);
    }

    public boolean isTokenExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }
}

exemple of code i want
     */

    private final RefreshTokenRepository refreshTokenRepository;
    @Value("${jwt.refreshExpirationMs}")
    private Long refreshExpirationMs;
    private final UserRepository userRepository;


    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    public RefreshToken createRefreshToken(Long userId){
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setToken(UUID.randomUUID().toString()); //todo : use SecureRandom instead of UUID
        refreshToken.setExpiryDate(LocalDateTime.now().plusNanos(refreshExpirationMs*1000)); //no plusMillis method
        refreshToken.setUser(userRepository.findById(userId).get());

        refreshToken.setRevoked(false);
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }
}


