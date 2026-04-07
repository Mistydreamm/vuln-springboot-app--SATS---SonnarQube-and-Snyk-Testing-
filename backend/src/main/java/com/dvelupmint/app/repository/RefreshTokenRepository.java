package com.dvelupmint.app.repository;

import com.dvelupmint.app.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByTokenAndRevokedFalse(String token);
    void revokeAllByUserId(Long userId);
    void deleteByExpiryDateBefore(Instant now);
}