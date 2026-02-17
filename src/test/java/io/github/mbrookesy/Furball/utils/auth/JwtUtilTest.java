package io.github.mbrookesy.Furball.utils.auth;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
    }

    @Test
    void generateToken_returnsNonNullToken() {
        String token = jwtUtil.generateToken("test@example.com");

        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void extractEmail_returnsCorrectEmail() {
        String email = "test@example.com";
        String token = jwtUtil.generateToken(email);

        String extractedEmail = jwtUtil.extractEmail(token);

        assertEquals(email, extractedEmail);
    }

    @Test
    void generatedToken_isNotExpiredImmediately() {
        String token = jwtUtil.generateToken("test@example.com");

        boolean expired = jwtUtil.isTokenExpired(token);

        assertFalse(expired);
    }

    @Test
    void tokenWithPastExpiration_isExpired() {
        String expiredToken = io.jsonwebtoken.Jwts.builder()
                .setSubject("test@example.com")
                .setIssuedAt(new java.util.Date(System.currentTimeMillis() - 10_000))
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 5_000))
                .signWith(
                        io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                                "this_is_a_very_long_secret_key_that_should_be_in_env_vars"
                                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)
                        ),
                        io.jsonwebtoken.SignatureAlgorithm.HS256
                )
                .compact();

        assertThrows(ExpiredJwtException.class, () ->
                jwtUtil.isTokenExpired(expiredToken)
        );
    }

    @Test
    void extractEmail_throwsExceptionForInvalidToken() {
        String invalidToken = "not.a.real.jwt";

        assertThrows(Exception.class, () ->
                jwtUtil.extractEmail(invalidToken)
        );
    }
}
