package com.bizztalk.auth.jwt_security.exceptionhandler;

import com.bizztalk.auth.jwt_security.authcontroller.AuthenticationResponse;
import com.bizztalk.auth.jwt_security.exception.InvalidJwtTokenException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;


@ControllerAdvice
public class GlobalExceptionHandler {

    @ResponseBody
    @ResponseStatus(value = HttpStatus.FORBIDDEN)
    @ExceptionHandler(value = { InvalidJwtTokenException.class })
    public AuthenticationResponse signatureExceptionHandler(Exception e) {
        return AuthenticationResponse.builder().error(e.getMessage()).build();
    }

}
