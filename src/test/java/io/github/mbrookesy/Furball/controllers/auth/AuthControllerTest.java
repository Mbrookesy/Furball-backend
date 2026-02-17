package io.github.mbrookesy.Furball.controllers.auth;

import io.github.mbrookesy.Furball.config.JwtAuthenticationFilter;
import io.github.mbrookesy.Furball.controllers.AuthController;
import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.models.auth.LoginUserModel;
import io.github.mbrookesy.Furball.models.auth.RegisterUserModel;
import io.github.mbrookesy.Furball.models.auth.RequestPasswordResetModel;
import io.github.mbrookesy.Furball.models.auth.ResetPasswordModel;
import io.github.mbrookesy.Furball.services.auth.AuthService;
import io.github.mbrookesy.Furball.services.auth.RegisterService;
import io.github.mbrookesy.Furball.services.auth.VerificationService;
import io.github.mbrookesy.Furball.utils.auth.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = AuthController.class,
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = JwtAuthenticationFilter.class
        )
)
@AutoConfigureMockMvc(addFilters = false)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private VerificationService verificationService;

    @MockitoBean
    private RegisterService registerService;

    @MockitoBean
    private JwtUtil jwtUtil;

    @Autowired
    private ObjectMapper objectMapper;

    @Nested
    @DisplayName("Login")
    public class Login {

        @Test
        @DisplayName("Login returns 200 when successful")
        void login_success() throws Exception {
            LoginUserModel request = new LoginUserModel("test@example.com", "testPassword");

            mockMvc.perform(
                            post("/auth/login")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    ).andExpect(status().isOk());

            verify(authService).checkLoginUser(any());
        }
    }

    @Test
    @DisplayName("Return 401 when there is invalid credentials")
    void login_invalid_credentials() throws Exception {
        LoginUserModel request = new LoginUserModel("test@example.com", "testPassword");

        doThrow(new InvalidCredentialsException())
                .when(authService).checkLoginUser(any());

        mockMvc.perform(
                        post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    @Test
    @DisplayName("Return 403 when email is not verified")
    void register_emails_exist() throws Exception {
        LoginUserModel request = new LoginUserModel("test@example.com", "testPassword");

        doThrow(new EmailNotVerifiedException("test@example.com"))
                .when(authService).checkLoginUser(any());

        mockMvc.perform(
                        post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("EMAIL_NOT_VERIFIED"))
                .andExpect(jsonPath("$.message").value("Email not verified: test@example.com"));
    }

    @Nested
    @DisplayName("Verify Email")
    public class VerifyEmail {

        @Test
        @DisplayName("Verify Email returns 200 when successful")
        void verify_email_success() throws Exception {
            mockMvc.perform(
                            put("/auth/verify-email")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .queryParam("token", "tokenValue")
                    ).andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User Verified"))
                    .andExpect(jsonPath("$.timestamp").exists());

            verify(verificationService).verifyUser(any());
        }

        @Test
        @DisplayName("Return 400 when the user is already verified")
        void verify_email_user_already_verified() throws Exception {

            doThrow(new UserAlreadyVerifiedException())
                    .when(verificationService).verifyUser(any());

            mockMvc.perform(
                            put("/auth/verify-email")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .queryParam("token", "tokenValue")
                    )
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").value("USER_ALREADY_VERIFIED"))
                    .andExpect(jsonPath("$.message").value("User already verified"));
        }

        @Test
        @DisplayName("Return 400 when the token isn't valid")
        void verify_email_token_not_valid() throws Exception {

            doThrow(new TokenNotValidException())
                    .when(verificationService).verifyUser(any());

            mockMvc.perform(
                            put("/auth/verify-email")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .queryParam("token", "tokenValue")
                    )
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").value("TOKEN_NOT_VALID"))
                    .andExpect(jsonPath("$.message").value("Supplied token not valid"));
        }
    }
    @Nested
    @DisplayName("Request Password Reset")
    class RequestPasswordReset {

        @Test
        @DisplayName("Returns 200 and triggers token creation when user exists")
        void request_password_reset_user_exists() throws Exception {
            RequestPasswordResetModel request =
                    new RequestPasswordResetModel("test@example.com");

            UserEntity user = new UserEntity();
            user.setEmail("test@example.com");

            when(authService.checkUserExists("test@example.com"))
                    .thenReturn(Optional.of(user));

            mockMvc.perform(
                            post("/auth/request-password-reset")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Reset Request Performed"))
                    .andExpect(jsonPath("$.timestamp").exists());

            verify(registerService)
                    .invalidateExistingTokensAndCreateNewResetToken(user);
        }

        @Test
        @DisplayName("Returns 200 and does nothing when user does not exist")
        void request_password_reset_user_does_not_exist() throws Exception {
            RequestPasswordResetModel request =
                    new RequestPasswordResetModel("missing@example.com");

            when(authService.checkUserExists("missing@example.com"))
                    .thenReturn(Optional.empty());

            mockMvc.perform(
                            post("/auth/request-password-reset")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Reset Request Performed"));

            verify(registerService, never())
                    .invalidateExistingTokensAndCreateNewResetToken(any());
        }
    }
    @Nested
    @DisplayName("Reset Password")
    class ResetPassword {

        @Test
        @DisplayName("Returns 200 when password reset succeeds")
        void reset_password_success() throws Exception {
            ResetPasswordModel request =
                    new ResetPasswordModel("newStrongPassword");

            mockMvc.perform(
                            patch("/auth/reset-password")
                                    .queryParam("token", "valid-token")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Password Changed"))
                    .andExpect(jsonPath("$.timestamp").exists());

            verify(verificationService)
                    .checkTokenAndChangePassword("valid-token", "newStrongPassword");
        }

        @Test
        @DisplayName("Returns 400 when token is invalid")
        void reset_password_invalid_token() throws Exception {
            ResetPasswordModel request =
                    new ResetPasswordModel("newStrongPassword");

            doThrow(new TokenNotValidException())
                    .when(verificationService)
                    .checkTokenAndChangePassword(any(), any());

            mockMvc.perform(
                            patch("/auth/reset-password")
                                    .queryParam("token", "bad-token")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").value("TOKEN_NOT_VALID"))
                    .andExpect(jsonPath("$.message").value("Supplied token not valid"));
        }
    }

    @Nested
    @DisplayName("Register")
    class Register {

        @Test
        @DisplayName("Register returns 201 when successful")
        void register_success() throws Exception {
            RegisterUserModel request = new RegisterUserModel(
                    "test@example.com",
                    "username",
                    "password123"
            );

            mockMvc.perform(
                            post("/auth/register")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.message").value("User registered successfully"))
                    .andExpect(jsonPath("$.timestamp").exists());

            verify(authService).checkForExistingFields(any());
            verify(authService).hashPasswordForUser(any());
            verify(registerService).registerAndStoreToken(any());
        }

        @Test
        @DisplayName("Register returns 400 when email already exists")
        void register_email_exists() throws Exception {
            RegisterUserModel request = new RegisterUserModel(
                    "test@example.com",
                    "username",
                    "password123"
            );

            doThrow(new EmailAlreadyExistsException("test@example.com"))
                    .when(authService).checkForExistingFields(any());

            mockMvc.perform(
                            post("/auth/register")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").value("EMAIL_ALREADY_EXISTS"))
                    .andExpect(jsonPath("$.message").value("Email already exists: test@example.com"));
        }

        @Test
        @DisplayName("Register returns 409 when username already exists")
        void register_username_exists() throws Exception {
            RegisterUserModel request = new RegisterUserModel(
                    "test@example.com",
                    "username",
                    "password123"
            );

            doThrow(new UsernameAlreadyExistsException("username"))
                    .when(authService).checkForExistingFields(any());

            mockMvc.perform(
                            post("/auth/register")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(request))
                    )
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.errorCode").value("USERNAME_ALREADY_EXISTS"))
                    .andExpect(jsonPath("$.message").value("Username already exists: username"));
        }
    }
}
