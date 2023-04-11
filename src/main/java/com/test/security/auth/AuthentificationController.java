package com.test.security.auth;

import com.test.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthentificationController {
    private  final AuthenticationService authenticationService;
    @PostMapping("/register")
    public ResponseEntity<AuthentificationResponse> register(@RequestBody RegisterRequest request ){
        return ResponseEntity.ok(authenticationService.register(request));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthentificationResponse> authenticate(@RequestBody AuthentificationRequest request ){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
