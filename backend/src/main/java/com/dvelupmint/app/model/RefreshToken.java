package com.dvelupmint.app.model;

import jakarta.persistence.*;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String token;
    private LocalDateTime expiryDate;
    private boolean revoked;
    @ManyToOne
    private User user;
    private Instant createdAt;
    private String replacedByToken;

    public RefreshToken(Long id, String token, LocalDateTime expiryDate, boolean revoked, User user, Instant createdAt, String replacedByToken) {
        this.id = id;
        this.token = token;
        this.expiryDate = expiryDate;
        this.revoked = revoked;
        this.user = user;
        this.createdAt = createdAt;
        this.replacedByToken = replacedByToken;
    }

    public RefreshToken() {

    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(LocalDate expiryDate) {
        this.expiryDate = expiryDate.atStartOfDay();
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getReplacedByToken() {
        return replacedByToken;
    }

    public void setReplacedByToken(String replacedByToken) {
        this.replacedByToken = replacedByToken;
    }

}
