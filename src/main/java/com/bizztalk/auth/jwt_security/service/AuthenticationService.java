package com.bizztalk.auth.jwt_security.service;
import com.bizztalk.auth.jwt_security.authcontroller.AuthenticationRequest;
import com.bizztalk.auth.jwt_security.authcontroller.AuthenticationResponse;
import com.bizztalk.auth.jwt_security.authcontroller.RegisterRequest;
import com.bizztalk.auth.jwt_security.entity.Role;
import com.bizztalk.auth.jwt_security.entity.User;
import com.bizztalk.auth.jwt_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        log.info("Register Service started.");
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        log.info("User successfully registered: {}", user);
        var jwtToken = jwtService.generateToken(user);
        log.info("Token successfully generated: {}", jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        log.info("User successfully authenticated: {}", request.getEmail());
        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        log.info("Token: {}", jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }
}
