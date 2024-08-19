package com.bizztalk.auth.jwt_security.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
@Slf4j
public class DemoController {

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/hello-admin")
    public String greetingAdmin(){
        log.info("demo endpoint triggered");
        return "Hello from secure endpoint.";
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/hello-user")
    public String greeting(){
        log.info("demo endpoint triggered");
        return "Hello from secure endpoint.";
    }
}
