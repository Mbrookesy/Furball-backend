package io.github.mbrookesy.Furball.repositories.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    boolean existsByEmailIgnoreCase(String email);
    boolean existsByUsernameIgnoreCase(String username);
    Optional<UserEntity> findByEmailIgnoreCase(String email);

}
