package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.entities.auth.VerificationTokenEntity;
import io.github.mbrookesy.Furball.models.auth.TokenType;
import io.github.mbrookesy.Furball.repositories.auth.VerificationTokenRepository;
import io.github.mbrookesy.Furball.utils.auth.TokenHashUtil;
import io.github.mbrookesy.Furball.utils.auth.TokenNotValidException;
import io.github.mbrookesy.Furball.utils.auth.UserAlreadyVerifiedException;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@Transactional
public class VerificationService {

    private final VerificationTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;

    public VerificationService(VerificationTokenRepository tokenRepository, PasswordEncoder passwordEncoder) {
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void checkTokenAndChangePassword(String token, String password) {
        String hashedToken = TokenHashUtil.sha256(token);

        VerificationTokenEntity tokenEntity = tokenRepository
                .findByTokenHash(hashedToken)
                .orElseThrow(TokenNotValidException::new);

        if (tokenEntity.getExpiresAt().isBefore(Instant.now())) {
            throw new TokenNotValidException();
        }

        if (tokenEntity.getUsed()) {
            throw new TokenNotValidException();
        }

        if (tokenEntity.getTokenType() != TokenType.RESET_PASSWORD) {
            throw new TokenNotValidException();
        }

        UserEntity user = tokenEntity.getUser();

        String hashedPassword = passwordEncoder.encode(password);
        user.setPasswordHash(hashedPassword);

        tokenRepository.markAllTokensAsUsedForUserAndType(user, TokenType.RESET_PASSWORD);
        tokenEntity.markTokenAsUsed();
    }

    public void verifyUser(String token) {
        String hashedToken = TokenHashUtil.sha256(token);

        VerificationTokenEntity tokenEntity = tokenRepository.findByTokenHash(hashedToken).orElseThrow(TokenNotValidException::new);

        if(tokenEntity.getExpiresAt().isBefore(Instant.now())) {
            throw new TokenNotValidException();
        }

        if(tokenEntity.getUsed()) {
            throw new TokenNotValidException();
        }

        if(tokenEntity.getTokenType() != TokenType.VERIFY_EMAIL) {
            throw new TokenNotValidException();
        }

        if (tokenEntity.getUser().isVerified()) {
            throw new UserAlreadyVerifiedException();
        }

        tokenEntity.markTokenAsUsed();
        tokenEntity.getUser().markVerified();
    }

}