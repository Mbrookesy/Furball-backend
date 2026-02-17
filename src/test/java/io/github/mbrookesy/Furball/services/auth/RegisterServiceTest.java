package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.entities.auth.VerificationTokenEntity;
import io.github.mbrookesy.Furball.models.auth.RegisterUserModel;
import io.github.mbrookesy.Furball.models.auth.TokenType;
import io.github.mbrookesy.Furball.repositories.auth.UserRepository;
import io.github.mbrookesy.Furball.repositories.auth.VerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegisterServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private VerificationTokenRepository tokenRepository;

    @InjectMocks
    private RegisterService registerService;

    private RegisterUserModel registerUserModel;

    @BeforeEach
    void setUp() {
        registerUserModel =
                new RegisterUserModel("testuser", "test@example.com", "password");
    }

    @Test
    void registerAndStoreToken_saves_user_and_token() {
        when(userRepository.save(any(UserEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        when(tokenRepository.save(any(VerificationTokenEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        registerService.registerAndStoreToken(registerUserModel);

        verify(userRepository, times(1)).save(any(UserEntity.class));
        verify(tokenRepository, times(1)).save(any(VerificationTokenEntity.class));
    }

    @Test
    void createAndStoreToken_succeeds_first_attempt() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");

        when(tokenRepository.save(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String token = registerService.createAndStoreToken(user, TokenType.VERIFY_EMAIL);

        assertNotNull(token);

        verify(tokenRepository, times(1)).save(any());
    }

    @Test
    void createAndStoreToken_retries_on_unique_constraint_violation() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");

        DataIntegrityViolationException uniqueViolation =
                mock(DataIntegrityViolationException.class);

        Throwable cause = new RuntimeException(
                "verification_tokens_token_key"
        );

        when(uniqueViolation.getMostSpecificCause()).thenReturn(cause);

        when(tokenRepository.save(any()))
                .thenThrow(uniqueViolation)
                .thenAnswer(invocation -> invocation.getArgument(0));

        String token = registerService.createAndStoreToken(user, TokenType.VERIFY_EMAIL);

        assertNotNull(token);
        verify(tokenRepository, times(2)).save(any());
    }

    @Test
    void createAndStoreToken_throws_after_two_unique_collisions() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");

        DataIntegrityViolationException uniqueViolation =
                mock(DataIntegrityViolationException.class);

        Throwable cause = new RuntimeException(
                "verification_tokens_token_key"
        );

        when(uniqueViolation.getMostSpecificCause()).thenReturn(cause);

        when(tokenRepository.save(any()))
                .thenThrow(uniqueViolation);

        assertThrows(
                DataIntegrityViolationException.class,
                () -> registerService.createAndStoreToken(user, TokenType.VERIFY_EMAIL)
        );

        verify(tokenRepository, times(2)).save(any());
    }

    @Test
    void createAndStoreToken_does_not_retry_on_non_unique_violation() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");

        DataIntegrityViolationException otherViolation =
                mock(DataIntegrityViolationException.class);

        Throwable cause = new RuntimeException("some other constraint");

        when(otherViolation.getMostSpecificCause()).thenReturn(cause);

        when(tokenRepository.save(any()))
                .thenThrow(otherViolation);

        assertThrows(
                DataIntegrityViolationException.class,
                () -> registerService.createAndStoreToken(user, TokenType.VERIFY_EMAIL)
        );

        verify(tokenRepository, times(1)).save(any());
    }

    @Test
    void invalidateExistingTokensAndCreateNewResetToken_marks_old_tokens_and_creates_new_one() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");

        when(tokenRepository.save(any(VerificationTokenEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        registerService.invalidateExistingTokensAndCreateNewResetToken(user);

        verify(tokenRepository, times(1)).markAllTokensAsUsedForUserAndType(user, TokenType.RESET_PASSWORD);

        verify(tokenRepository, times(1)).save(any(VerificationTokenEntity.class));
    }

}
