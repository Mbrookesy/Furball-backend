package io.github.mbrookesy.Furball.utils.auth;

import org.springframework.http.HttpStatus;

public abstract class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    protected AuthException(HttpStatus status, String errorCode, String message) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
