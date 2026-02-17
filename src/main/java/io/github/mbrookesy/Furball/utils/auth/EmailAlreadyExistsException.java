package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public class EmailAlreadyExistsException extends AuthException {

    public EmailAlreadyExistsException(String email) {
        super(
                HttpStatus.BAD_REQUEST,
                "EMAIL_ALREADY_EXISTS",
                "Email already exists: " + email
        );
    }
}