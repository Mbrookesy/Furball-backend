package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.entities.auth.VerificationTokenEntity;
import io.github.mbrookesy.Furball.models.auth.TokenType;
import io.github.mbrookesy.Furball.repositories.auth.VerificationTokenRepository;
import io.github.mbrookesy.Furball.utils.auth.TokenHashUtil;
import io.github.mbrookesy.Furball.utils.auth.TokenNotValidException;
import io.github.mbrookesy.Furball.utils.auth.UserAlreadyVerifiedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerificationServiceTest {

    @Mock
    private VerificationTokenRepository tokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private VerificationService verificationService;

    private UserEntity user;
    private VerificationTokenEntity token;

    private static final String RAW_TOKEN = "raw-token";
    private static final String HASHED_TOKEN = TokenHashUtil.sha256(RAW_TOKEN);
    private static final String NEW_PASSWORD = "new-password";
    private static final String HASHED_PASSWORD = "hashed-password";

    @BeforeEach
    void setup() {
        user = spy(new UserEntity("test@example.com", "testuser", "password"));
        token = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.VERIFY_EMAIL,
                Instant.now().plusSeconds(3600)
        ));
    }

    @Test
    @DisplayName("Successfully verifies user with valid token")
    void verifyUser_success() {
        when(tokenRepository.findByTokenHash(HASHED_TOKEN)).thenReturn(Optional.of(token));

        verificationService.verifyUser(RAW_TOKEN);

        verify(token).markTokenAsUsed();
        verify(user).markVerified();
    }

    @Test
    @DisplayName("Throws when token does not exist")
    void verifyUser_tokenNotFound() {
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThrows(TokenNotValidException.class, () -> verificationService.verifyUser(RAW_TOKEN));

        verify(tokenRepository).findByTokenHash(HASHED_TOKEN);
    }

    @Test
    @DisplayName("Throws when token is expired")
    void verifyUser_tokenExpired() {
        VerificationTokenEntity expiredToken = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.VERIFY_EMAIL,
                Instant.now().minusSeconds(1)
        ));

        when(tokenRepository.findByTokenHash(HASHED_TOKEN)).thenReturn(Optional.of(expiredToken));

        assertThrows(TokenNotValidException.class, () -> verificationService.verifyUser(RAW_TOKEN));

        verify(expiredToken, never()).markTokenAsUsed();
        verify(user, never()).markVerified();
    }

    @Test
    @DisplayName("Throws when token has already been used")
    void verifyUser_tokenAlreadyUsed() {
        doReturn(true).when(token).getUsed();

        when(tokenRepository.findByTokenHash(HASHED_TOKEN)).thenReturn(Optional.of(token));

        assertThrows(TokenNotValidException.class, () -> verificationService.verifyUser(RAW_TOKEN));

        verify(token, never()).markTokenAsUsed();
        verify(user, never()).markVerified();
    }

    @Test
    @DisplayName("Throws when token type is not VERIFY_EMAIL")
    void verifyUser_wrongTokenType() {
        VerificationTokenEntity wrongTypeToken = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.RESET_PASSWORD,
                Instant.now().plusSeconds(3600)
        ));

        when(tokenRepository.findByTokenHash(HASHED_TOKEN)).thenReturn(Optional.of(wrongTypeToken));

        assertThrows(TokenNotValidException.class, () -> verificationService.verifyUser(RAW_TOKEN));

        verify(wrongTypeToken, never()).markTokenAsUsed();
        verify(user, never()).markVerified();
    }

    @Test
    @DisplayName("Throws when user is already verified")
    void verifyUser_userAlreadyVerified() {
        doReturn(true).when(user).isVerified();

        when(tokenRepository.findByTokenHash(HASHED_TOKEN)).thenReturn(Optional.of(token));

        assertThrows(UserAlreadyVerifiedException.class, () -> verificationService.verifyUser(RAW_TOKEN));

        verify(token, never()).markTokenAsUsed();
    }

    @Test
    @DisplayName("Successfully resets password with valid RESET_PASSWORD token")
    void resetPassword_success() {
        VerificationTokenEntity resetToken = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.RESET_PASSWORD,
                Instant.now().plusSeconds(3600)
        ));

        when(tokenRepository.findByTokenHash(HASHED_TOKEN))
                .thenReturn(Optional.of(resetToken));

        when(passwordEncoder.encode(NEW_PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        verificationService.checkTokenAndChangePassword(RAW_TOKEN, NEW_PASSWORD);

        verify(passwordEncoder).encode(NEW_PASSWORD);
        verify(user).setPasswordHash(HASHED_PASSWORD);
        verify(tokenRepository)
                .markAllTokensAsUsedForUserAndType(user, TokenType.RESET_PASSWORD);
        verify(resetToken).markTokenAsUsed();
    }

    @Test
    @DisplayName("Throws when reset token does not exist")
    void resetPassword_tokenNotFound() {
        when(tokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.empty());

        assertThrows(
                TokenNotValidException.class,
                () -> verificationService.checkTokenAndChangePassword(RAW_TOKEN, NEW_PASSWORD)
        );

        verify(tokenRepository).findByTokenHash(HASHED_TOKEN);
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    @DisplayName("Throws when reset token is expired")
    void resetPassword_tokenExpired() {
        VerificationTokenEntity expiredToken = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.RESET_PASSWORD,
                Instant.now().minusSeconds(1)
        ));

        when(tokenRepository.findByTokenHash(HASHED_TOKEN))
                .thenReturn(Optional.of(expiredToken));

        assertThrows(
                TokenNotValidException.class,
                () -> verificationService.checkTokenAndChangePassword(RAW_TOKEN, NEW_PASSWORD)
        );

        verify(expiredToken, never()).markTokenAsUsed();
        verify(user, never()).setPasswordHash(any());
    }

    @Test
    @DisplayName("Throws when reset token has already been used")
    void resetPassword_tokenAlreadyUsed() {
        VerificationTokenEntity usedToken = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.RESET_PASSWORD,
                Instant.now().plusSeconds(3600)
        ));

        doReturn(true).when(usedToken).getUsed();

        when(tokenRepository.findByTokenHash(HASHED_TOKEN))
                .thenReturn(Optional.of(usedToken));

        assertThrows(
                TokenNotValidException.class,
                () -> verificationService.checkTokenAndChangePassword(RAW_TOKEN, NEW_PASSWORD)
        );

        verify(usedToken, never()).markTokenAsUsed();
        verify(user, never()).setPasswordHash(any());
    }

    @Test
    @DisplayName("Throws when token type is not RESET_PASSWORD")
    void resetPassword_wrongTokenType() {
        VerificationTokenEntity wrongTypeToken = spy(new VerificationTokenEntity(
                user,
                HASHED_TOKEN,
                TokenType.VERIFY_EMAIL,
                Instant.now().plusSeconds(3600)
        ));

        when(tokenRepository.findByTokenHash(HASHED_TOKEN))
                .thenReturn(Optional.of(wrongTypeToken));

        assertThrows(
                TokenNotValidException.class,
                () -> verificationService.checkTokenAndChangePassword(RAW_TOKEN, NEW_PASSWORD)
        );

        verify(wrongTypeToken, never()).markTokenAsUsed();
        verify(user, never()).setPasswordHash(any());
    }
}
