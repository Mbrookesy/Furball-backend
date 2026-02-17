package io.github.mbrookesy.Furball.repository.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.repositories.auth.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void existsByEmailIgnoreCase_returns_true_when_exists() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");
        userRepository.save(user);

        boolean exists = userRepository.existsByEmailIgnoreCase("TEST@EXAMPLE.COM");

        assertTrue(exists);
    }

    @Test
    void existsByUsernameIgnoreCase_returns_true_when_exists() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");
        userRepository.save(user);

        boolean exists = userRepository.existsByUsernameIgnoreCase("TESTUSER");

        assertTrue(exists);
    }

    @Test
    void existsByEmailIgnoreCase_returns_false_when_not_exists() {
        boolean exists = userRepository.existsByEmailIgnoreCase("missing@example.com");

        assertFalse(exists);
    }

    @Test
    void findByEmailIgnoreCase_returns_empty_when_not_found() {
        Optional<UserEntity> found = userRepository.findByEmailIgnoreCase("missing@example.com");

        assertTrue(found.isEmpty());
    }

    @Test
    void findByEmailIgnoreCase_returns_user_when_found() {
        UserEntity user = new UserEntity("test@example.com", "testuser", "pw");
        userRepository.save(user);

        Optional<UserEntity> foundUser =
                userRepository.findByEmailIgnoreCase("TEST@EXAMPLE.COM");

        assertTrue(foundUser.isPresent());
        assertEquals("test@example.com", foundUser.get().getEmail());
    }
}