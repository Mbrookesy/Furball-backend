package io.github.mbrookesy.Furball.utils.auth;

import io.github.mbrookesy.Furball.models.auth.RegisterErrorResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

class AuthExceptionHandlerTest {

    private final AuthExceptionHandler handler = new AuthExceptionHandler();

    @Test
    void handleAuthException_returns_expected_response() {
        AuthException exception = new TestAuthException(
                HttpStatus.FORBIDDEN,
                "EMAIL_NOT_VERIFIED",
                "Email not verified: test@example.com"
        );

        ResponseEntity<RegisterErrorResponse> response =
                handler.handleAuthException(exception);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        RegisterErrorResponse body = response.getBody();
        assertNotNull(body);

        assertEquals("EMAIL_NOT_VERIFIED", body.errorCode());
        assertEquals("Email not verified: test@example.com", body.message());
        assertNotNull(body.timestamp());
    }

    private static class TestAuthException extends AuthException {
        TestAuthException(HttpStatus status, String errorCode, String message) {
            super(status, errorCode, message);
        }
    }
}
