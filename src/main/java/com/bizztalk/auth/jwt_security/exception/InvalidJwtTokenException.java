package com.bizztalk.auth.jwt_security.exception;

public class InvalidJwtTokenException extends RuntimeException {
    public InvalidJwtTokenException(String msg){
        super(msg);
    }
}
