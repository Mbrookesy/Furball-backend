package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.RefreshToken;
import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.repositories.auth.RefreshTokenRepository;
import io.github.mbrookesy.Furball.utils.auth.TokenHashUtil;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private static final long REFRESH_TOKEN_DURATION_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public RefreshToken createRefreshToken(UserEntity user) {
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(REFRESH_TOKEN_DURATION_MS));

        String rawToken = UUID.randomUUID().toString();
        String hashed = TokenHashUtil.sha256(rawToken);

        token.setToken(hashed);

        return refreshTokenRepository.save(token);
    }

    public boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }

    public void deleteByUser(UserEntity user) {
        refreshTokenRepository.deleteByUser(user);
    }

    public RefreshToken findByRawToken(String rawToken) {
        String hash = TokenHashUtil.sha256(rawToken);
        return refreshTokenRepository.findByToken(hash)
                .orElseThrow();
    }
}
