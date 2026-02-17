package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public class UsernameAlreadyExistsException extends AuthException {

    public UsernameAlreadyExistsException(String username) {
        super(
                HttpStatus.CONFLICT,
                "USERNAME_ALREADY_EXISTS",
                "Username already exists: " + username
        );
    }
}
