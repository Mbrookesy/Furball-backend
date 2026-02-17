package io.github.mbrookesy.Furball.models.auth;

import java.time.Instant;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        Instant issuedAt
) {}
