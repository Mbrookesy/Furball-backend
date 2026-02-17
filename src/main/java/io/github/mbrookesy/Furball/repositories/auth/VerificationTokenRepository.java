package io.github.mbrookesy.Furball.repositories.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.entities.auth.VerificationTokenEntity;
import io.github.mbrookesy.Furball.models.auth.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepository extends JpaRepository<VerificationTokenEntity, UUID> {
    Optional<VerificationTokenEntity> findByTokenHash(String tokenHash);

    @Modifying
    @Query("""
        update VerificationTokenEntity t
        set t.used = true
        where t.user = :user
          and t.tokenType = :tokenType
          and t.used = false
    """)
    int markAllTokensAsUsedForUserAndType(
            @Param("user") UserEntity user,
            @Param("tokenType") TokenType tokenType
    );

}
