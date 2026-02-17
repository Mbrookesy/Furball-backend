package io.github.mbrookesy.Furball.services.auth;

import io.github.mbrookesy.Furball.entities.auth.UserEntity;
import io.github.mbrookesy.Furball.models.auth.LoginUserModel;
import io.github.mbrookesy.Furball.models.auth.RegisterUserModel;
import io.github.mbrookesy.Furball.repositories.auth.UserRepository;
import io.github.mbrookesy.Furball.utils.auth.EmailAlreadyExistsException;
import io.github.mbrookesy.Furball.utils.auth.EmailNotVerifiedException;
import io.github.mbrookesy.Furball.utils.auth.InvalidCredentialsException;
import io.github.mbrookesy.Furball.utils.auth.UsernameAlreadyExistsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;


    public AuthService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    public void checkForExistingFields(RegisterUserModel user) {
        if (userRepository.existsByEmailIgnoreCase(user.email())) {
            throw new EmailAlreadyExistsException(user.email());
        } else if (userRepository.existsByUsernameIgnoreCase(user.username())) {
            throw new UsernameAlreadyExistsException(user.username());
        }
    }

    public RegisterUserModel hashPasswordForUser(RegisterUserModel user) {
            String hashedPassword = passwordEncoder.encode(user.password());
            return new RegisterUserModel(user.username(), user.email(), hashedPassword);
    }

    public UserEntity checkLoginUser(LoginUserModel login) {

        UserEntity user = userRepository.findByEmailIgnoreCase(login.email())
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(login.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        if (!user.isVerified()) {
            throw new EmailNotVerifiedException(login.email());
        }

        return user;
    }

    public Optional<UserEntity> checkUserExists(String email) {
        return userRepository.findByEmailIgnoreCase(email);
    }
}
