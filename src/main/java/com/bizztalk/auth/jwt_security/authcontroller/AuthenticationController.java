package com.bizztalk.auth.jwt_security.authcontroller;

import com.bizztalk.auth.jwt_security.service.AuthenticationService;
import com.bizztalk.auth.jwt_security.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

  private final AuthenticationService authService;
  private final JwtService jwtService;

  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody RegisterRequest request
  ) {
    log.info("Registration started");
    return ResponseEntity.ok(authService.register(request));
  }
  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(
      @RequestBody AuthenticationRequest request
  ) {
    return ResponseEntity.ok(authService.authenticate(request));
  }

  @PostMapping("/logout")
  public ResponseEntity<String> logout(@RequestHeader("Authorization") String token){
    if(token!=null){
      jwtService.blacklistToken(token);
      return ResponseEntity.ok("Logged out - token revoked");
    }
    else{
      return ResponseEntity.ok("Authorization header cannot be null");
    }
  }

}