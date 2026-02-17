package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public class TokenNotValidException extends AuthException {

    public TokenNotValidException() {
        super(
                HttpStatus.BAD_REQUEST,
                "TOKEN_NOT_VALID",
                "Supplied token not valid"
        );
    }
}
