package io.github.mbrookesy.Furball.models.auth;

import java.time.Duration;
import java.time.Instant;

public enum TokenType {

    VERIFY_EMAIL(Duration.ofDays(1)),
    RESET_PASSWORD(Duration.ofMinutes(30)),
    CHANGE_EMAIL(Duration.ofHours(2));

    private final Duration ttl;

    TokenType(Duration ttl) {
        this.ttl = ttl;
    }

    public Instant expiresAt(Instant now) {
        return now.plus(ttl);
    }
}
