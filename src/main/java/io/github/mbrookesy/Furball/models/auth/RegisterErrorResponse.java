package io.github.mbrookesy.Furball.models.auth;

import java.time.Instant;

public record RegisterErrorResponse(String errorCode, String message, Instant timestamp) { }
