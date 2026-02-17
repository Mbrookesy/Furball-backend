package io.github.mbrookesy.Furball.utils.auth;

import io.github.mbrookesy.Furball.models.auth.RegisterErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

@RestControllerAdvice
public class AuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<RegisterErrorResponse> handleAuthException(AuthException ex) {
        log.warn("Auth error occurred: errorCode={}, status={}", ex.getErrorCode(), ex.getStatus());

        return ResponseEntity
                .status(ex.getStatus())
                .body(new RegisterErrorResponse(
                        ex.getErrorCode(),
                        ex.getMessage(),
                        Instant.now()
                ));
    }
}
