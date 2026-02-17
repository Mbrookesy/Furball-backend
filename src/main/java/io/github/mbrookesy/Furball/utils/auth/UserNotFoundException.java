package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends AuthException {

    public UserNotFoundException() {
        super(
                HttpStatus.NOT_FOUND,
                "USER_NOT_FOUND",
                "User not found"
        );
    }
}
