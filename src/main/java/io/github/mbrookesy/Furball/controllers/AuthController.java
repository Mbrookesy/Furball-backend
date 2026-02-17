package io.github.mbrookesy.Furball.controllers;

import io.github.mbrookesy.Furball.entities.auth.RefreshToken;
import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.models.auth.*;
import io.github.mbrookesy.Furball.services.auth.AuthService;
import io.github.mbrookesy.Furball.services.auth.RefreshTokenService;
import io.github.mbrookesy.Furball.services.auth.RegisterService;
import io.github.mbrookesy.Furball.services.auth.VerificationService;
import io.github.mbrookesy.Furball.services.mail.EmailService;
import io.github.mbrookesy.Furball.utils.auth.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;
    private final VerificationService verificationService;
    private final RegisterService registerService;
    private final EmailService emailService;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtil jwtUtil;

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    public AuthController(AuthService authService, VerificationService verificationService, RegisterService registerService, EmailService emailService, RefreshTokenService refreshTokenService, JwtUtil jwtUtil) {
        this.authService = authService;
        this.verificationService = verificationService;
        this.registerService = registerService;
        this.emailService = emailService;
        this.refreshTokenService = refreshTokenService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping(value = "/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<AuthSuccessResponse> registerUser(@RequestBody RegisterUserModel user) {
        log.info("Starting registration process");
        authService.checkForExistingFields(user);

        RegisterUserModel userWithHash = authService.hashPasswordForUser(user);

        String token = registerService.registerAndStoreToken(userWithHash);

        //TODO: Change to send a legit email with the correct link for the frontend
        emailService.sendEmail(userWithHash.email(), "Furball: Verify your email", "Please verify your email via https://localhost:8443/auth/verify-email?token=" + token);

        log.info("User successfully registered");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new AuthSuccessResponse(
                      "User registered successfully",
                        Instant.now()
                ));
    }

    @PostMapping(value = "/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<LoginResponse> loginUser(@RequestBody LoginUserModel user) {
        UserEntity loggedInUser = authService.checkLoginUser(user);

        String jwt = jwtUtil.generateToken(loggedInUser.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(loggedInUser);


        log.info("User successfully logged in");

        return ResponseEntity.ok(
                new LoginResponse(jwt, refreshToken.getToken(), Instant.now())
        );
    }


    @PutMapping(value = "/verify-email", produces = "application/json")
    public ResponseEntity<AuthSuccessResponse> verificationEmail(@RequestParam(value = "token") String token) {
        verificationService.verifyUser(token);

        log.info("User successfully Verified");
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new AuthSuccessResponse(
                        "User Verified",
                        Instant.now()
                ));
    }

    @PostMapping(value = "/request-password-reset", consumes = "application/json", produces = "application/json")
    public ResponseEntity<AuthSuccessResponse> requestPasswordReset(@RequestBody RequestPasswordResetModel requestBody) {
        log.info("Requesting password reset...");

        Optional<UserEntity> user = authService.checkUserExists(requestBody.email());

        user.ifPresent(value -> {
            String token = registerService.invalidateExistingTokensAndCreateNewResetToken(value);
            emailService.sendEmail(value.getEmail(), "Furball: Reset Password", "Please reset your password via https://localhost:8443/auth/reset-password?token=" + token);

        });

        return ResponseEntity.status(HttpStatus.OK).body(new AuthSuccessResponse("Reset Request Performed", Instant.now()));
    }

    @PatchMapping(value = "/reset-password", produces = "application/json")
    public ResponseEntity<AuthSuccessResponse> resetPassword(@RequestBody ResetPasswordModel requestBody, @RequestParam(value = "token") String token) {
        log.info("starting rest password");
        verificationService.checkTokenAndChangePassword(token, requestBody.password());

        log.info("Password reset");
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new AuthSuccessResponse(
                        "Password Changed",
                        Instant.now()
                ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody String refreshTokenString) {
        log.info("Attempting to refresh JWT");
        try {
            RefreshToken refreshToken = refreshTokenService.findByRawToken(refreshTokenString);

            if (refreshTokenService.isExpired(refreshToken)) {
                return ResponseEntity.status(403).body("Refresh token expired. Please login again.");
            }

            String newJwt = jwtUtil.generateToken(refreshToken.getUser().getEmail());
            return ResponseEntity.ok().body("{\"token\":\"" + newJwt + "\"}");

        } catch (Exception e) {
            return ResponseEntity.status(403).body("Invalid refresh token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Authentication auth) {
        UserEntity user = (UserEntity) auth.getPrincipal();
        refreshTokenService.deleteByUser(user);
        return ResponseEntity.noContent().build();
    }
}
