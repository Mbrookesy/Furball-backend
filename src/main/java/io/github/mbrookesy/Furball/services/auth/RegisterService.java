package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.entities.auth.VerificationTokenEntity;
import io.github.mbrookesy.Furball.models.auth.RegisterUserModel;
import io.github.mbrookesy.Furball.models.auth.TokenType;
import io.github.mbrookesy.Furball.repositories.auth.UserRepository;
import io.github.mbrookesy.Furball.repositories.auth.VerificationTokenRepository;
import io.github.mbrookesy.Furball.utils.auth.InvalidCredentialsException;
import io.github.mbrookesy.Furball.utils.auth.TokenHashUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@Transactional
public class RegisterService {
    private final VerificationTokenRepository repository;
    private final UserRepository userRepository;

    private static Logger log = LoggerFactory.getLogger(RegisterService.class);

    public RegisterService(VerificationTokenRepository repository, UserRepository userRepository) {
        this.repository = repository;
        this.userRepository = userRepository;
    }

    public String registerAndStoreToken(RegisterUserModel user) {
        UserEntity userToSave = new UserEntity(user.email(), user.username(), user.password());

        userRepository.save(userToSave);

        return createAndStoreToken(userToSave, TokenType.VERIFY_EMAIL);
    }

    public String createAndStoreToken(
            UserEntity user,
            TokenType tokenType
    ) {
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                String rawToken = UUID.randomUUID().toString();
                String hashedToken = TokenHashUtil.sha256(rawToken);

                Instant expiresAt = tokenType.expiresAt(Instant.now());

                VerificationTokenEntity entity = new VerificationTokenEntity(user, hashedToken, tokenType, expiresAt);
                repository.save(entity);
                return rawToken;
            } catch (DataIntegrityViolationException ex) {
                if (!isUniqueConstraintViolation(ex) || attempt == 1) {
                    throw ex;
                }
                log.warn("Token collision detected, retrying...");
            }
        }
        throw new IllegalStateException("Unreachable");
    }

    public String invalidateExistingTokensAndCreateNewResetToken(UserEntity user) {
        repository.markAllTokensAsUsedForUserAndType(user, TokenType.RESET_PASSWORD);
        return createAndStoreToken(user, TokenType.RESET_PASSWORD);
    }

    private boolean isUniqueConstraintViolation(DataIntegrityViolationException ex) {
        return ex.getMostSpecificCause()
                .getMessage()
                .toLowerCase()
                .contains("verification_tokens_token_key");
    }
}
