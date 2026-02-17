package io.github.mbrookesy.Furball.models.auth;

import java.time.Instant;

public record AuthSuccessResponse(String message, Instant timestamp) {
}
