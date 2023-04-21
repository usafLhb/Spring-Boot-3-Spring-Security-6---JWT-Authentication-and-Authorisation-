package com.test.security.demo.DemoController;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
@RequestMapping("/api/v2")
@RequiredArgsConstructor
public class DemoController {
    @GetMapping("/all")
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello ljfisdf kjsdf");
    }

    @GetMapping("/example")
    public ResponseEntity<?> getExample(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            if (authorities.stream().anyMatch(a -> a.getAuthority().equals("ADMIN"))) {
                // User has the ADMIN role, process the request
                return ResponseEntity.ok("Hello, ADMIN!");
            }
        }

        // User does not have the required role, return 403 Forbidden
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("You do not have permission to access this resource.");
    }
}
