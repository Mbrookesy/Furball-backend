package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.models.auth.LoginUserModel;
import io.github.mbrookesy.Furball.models.auth.RegisterUserModel;
import io.github.mbrookesy.Furball.repositories.auth.UserRepository;
import io.github.mbrookesy.Furball.utils.auth.EmailAlreadyExistsException;
import io.github.mbrookesy.Furball.utils.auth.EmailNotVerifiedException;
import io.github.mbrookesy.Furball.utils.auth.InvalidCredentialsException;
import io.github.mbrookesy.Furball.utils.auth.UsernameAlreadyExistsException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@Tag("unit")
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Nested
    @DisplayName("checkForExistingFields")
    class CheckForExistingFields {
        RegisterUserModel userModel = new RegisterUserModel("testUsername", "testEmail", "testPassword");

        @Test
        @DisplayName("Test that a user that doesn't exist wont throw an exception")
        void validUser() {
            when(userRepository.existsByEmailIgnoreCase(any())).thenReturn(false);
            when(userRepository.existsByUsernameIgnoreCase(any())).thenReturn(false);

            assertDoesNotThrow(() -> authService.checkForExistingFields(userModel));
        }

        @Test
        @DisplayName("Throws an exception when email already exists")
        void emailExists() {
            when(userRepository.existsByEmailIgnoreCase(any())).thenReturn(true);

            assertThrows(
                    EmailAlreadyExistsException.class,
                    () -> authService.checkForExistingFields(userModel)
            );
        }

        @Test
        @DisplayName("Throws an exception when username exists")
        void usernameExists() {
            when(userRepository.existsByEmailIgnoreCase(any())).thenReturn(false);
            when(userRepository.existsByUsernameIgnoreCase(any())).thenReturn(true);

            assertThrows(
                    UsernameAlreadyExistsException.class,
                    () -> authService.checkForExistingFields(userModel)
            );
        }
    }

    @Nested
    @DisplayName("hashPasswordForUser")
    class HashPasswordForUser {
        @Test
        @DisplayName("Returns a user with the hashed password after hashing it")
        void returnsUserWithHash() {
            RegisterUserModel userModel = new RegisterUserModel("testUsername", "testEmail", "testPassword");
            RegisterUserModel expectedModel = new RegisterUserModel("testUsername", "testEmail", "HashedPassword");
            when(passwordEncoder.encode(any())).thenReturn("HashedPassword");

            assertEquals(authService.hashPasswordForUser(userModel), expectedModel);
        }
    }

    @Nested
    @DisplayName("checkLoginUser")
    class CheckLoginUser {

        @Test
        @DisplayName("Throws InvalidCredentialsException when email does not exist")
        void checkLoginUser_throws_when_email_not_found() {
            LoginUserModel login = new LoginUserModel("test@example.com", "password");

            when(userRepository.findByEmailIgnoreCase(login.email())).thenReturn(Optional.empty());

            assertThrows(InvalidCredentialsException.class, () -> authService.checkLoginUser(login));
        }

        @Test
        @DisplayName("Throws InvalidCredentialsException when password is incorrect")
        void checkLoginUser_throws_when_password_is_wrong() {

            LoginUserModel login = new LoginUserModel("test@example.com", "wrong-password");

            UserEntity user = mock(UserEntity.class);

            when(userRepository.findByEmailIgnoreCase(login.email())).thenReturn(Optional.of(user));

            when(user.getPasswordHash()).thenReturn("hashed");
            when(passwordEncoder.matches(login.password(), "hashed")).thenReturn(false);

            assertThrows(InvalidCredentialsException.class, () -> authService.checkLoginUser(login));
        }

        @Test
        @DisplayName("Throws EmailNotVerifiedException when user is not verified")
        void checkLoginUser_throws_when_not_verified() {

            LoginUserModel login = new LoginUserModel("test@example.com", "correct-password");

            UserEntity user = mock(UserEntity.class);

            when(userRepository.findByEmailIgnoreCase(login.email())).thenReturn(Optional.of(user));

            when(user.getPasswordHash()).thenReturn("hashed");
            when(passwordEncoder.matches(login.password(), "hashed")).thenReturn(true);
            when(user.isVerified()).thenReturn(false);

            assertThrows(EmailNotVerifiedException.class, () -> authService.checkLoginUser(login));
        }

        @Test
        @DisplayName("Succeeds when credentials are valid and user is verified")
        void checkLoginUser_succeeds_when_valid() {

            LoginUserModel login = new LoginUserModel("test@example.com", "correct-password");

            UserEntity user = mock(UserEntity.class);

            when(userRepository.findByEmailIgnoreCase(login.email())).thenReturn(Optional.of(user));

            when(user.getPasswordHash()).thenReturn("hashed");
            when(passwordEncoder.matches(login.password(), "hashed")).thenReturn(true);
            when(user.isVerified()).thenReturn(true);

            assertDoesNotThrow(() -> authService.checkLoginUser(login));
        }
    }

}
