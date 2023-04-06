package com.kostas.spring.authentication.auth;

import com.kostas.spring.authentication.config.JwtService;
import com.kostas.spring.authentication.user.Role;
import com.kostas.spring.authentication.user.User;
import com.kostas.spring.authentication.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor

public class AuthenticationService {
private final UserRepository repository;
private final PasswordEncoder passwordEncoder;
private final JwtService jwtService;
private final AuthenticationManager authenticationManager;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);


    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) //passwordEncoder before saving to database
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        logger.info("Authenticating user with email: {}", request.getEmail());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.email)
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        AuthenticationResponse response = AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
        logger.info("User with email: {} authenticated successfully", request.getEmail());
        return response;
    }


}
