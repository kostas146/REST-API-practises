package com.kostas.spring.authentication.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
    return ResponseEntity.ok(service.register(request));
    }
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        logger.info("Authenticating user with email: {}", request.getEmail());
        AuthenticationResponse response = service.authenticate(request);
        logger.info("User with email: {} authenticated successfully", request.getEmail());
        return ResponseEntity.ok(response);
    }
    /*  Employ me  *//*  Employ me  *//*  Employ me  *//*  Employ me  *//*  Employ me  *//*  Employ me  */
}
