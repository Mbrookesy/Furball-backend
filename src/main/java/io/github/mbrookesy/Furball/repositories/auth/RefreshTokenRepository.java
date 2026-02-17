package io.github.mbrookesy.Furball.repositories.auth;

import io.github.mbrookesy.Furball.entities.auth.RefreshToken;
import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(UserEntity user);
}
