package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public class UserAlreadyVerifiedException extends AuthException {

    public UserAlreadyVerifiedException() {
        super(
                HttpStatus.BAD_REQUEST,
                "USER_ALREADY_VERIFIED",
                "User already verified"
        );
    }
}
