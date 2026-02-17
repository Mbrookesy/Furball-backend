package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public class EmailNotVerifiedException extends AuthException {

    public EmailNotVerifiedException(String email) {
        super(
                HttpStatus.FORBIDDEN,
                "EMAIL_NOT_VERIFIED",
                "Email not verified: " + email
        );
    }
}
