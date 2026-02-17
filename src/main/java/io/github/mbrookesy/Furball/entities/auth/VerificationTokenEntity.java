package io.github.mbrookesy.Furball.entities.auth;

import io.github.mbrookesy.Furball.models.auth.TokenType;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "verification_tokens")
public class VerificationTokenEntity {

    @Id
    @GeneratedValue
    private UUID tokenId;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType tokenType;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private Boolean used = false;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column
    private Instant usedAt;

    protected VerificationTokenEntity() {}

    public VerificationTokenEntity(UserEntity user, String tokenHash, TokenType tokenType, Instant expiresAt) {
        this.user = user;
        this.tokenHash = tokenHash;
        this.tokenType = tokenType;
        this.expiresAt = expiresAt;
    }


    public UserEntity getUser() {
        return user;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Boolean getUsed() {
        return used;
    }

    public void markTokenAsUsed() {
        this.used = true;
        this.usedAt = Instant.now();
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }
}
