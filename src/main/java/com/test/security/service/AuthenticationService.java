package com.test.security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.security.auth.AuthentificationRequest;
import com.test.security.auth.AuthentificationResponse;
import com.test.security.auth.RegisterRequest;
import com.test.security.token.Token;
import com.test.security.token.TokenRepository;
import com.test.security.token.TokenType;
import com.test.security.user.Role;
import com.test.security.user.User;
import com.test.security.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
  /*  private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthentificationResponse register(RegisterRequest request) {
        List<Role> roles = new ArrayList<Role>();
        roles.add(Role.USER);
       roles.add(Role.ADMIN);

        var user= User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(roles)
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthentificationResponse.builder()
                .token(jwtToken)
                .build();
    }
    public AuthentificationResponse authenticate(AuthentificationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user =userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthentificationResponse.builder()
                .token(jwtToken)
                .build();
    }
*/


    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
static String key_jwt;

    public AuthentificationResponse register(RegisterRequest request) {
        List<Role> roles = new ArrayList<Role>();
        roles.add(Role.USER);
        roles.add(Role.ADMIN);
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(roles)
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateToken(user);
        key_jwt=jwtToken;
        saveUserToken(savedUser, jwtToken);
        return AuthentificationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthentificationResponse authenticate(AuthentificationRequest  request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken =jwtService.generateToken(user);

         var refreshToken = jwtService.generateRefreshToken(user);


        List<Token> isTokenVdalid2 = tokenRepository.findAllByUser(user);
        boolean anyExpiredAndRevoked = isTokenVdalid2.stream()
                .anyMatch(t -> t.isExpired() && t.isRevoked());

        //SI isRevoked ET isExpired EST 0 LA 1ER TENTATIVE ALORS
        if(!anyExpiredAndRevoked){
            revokeAllUserTokens(user);
            saveUserToken(user, jwtToken);
        }
        //SI isRevoked ET isExpired EST 1 (IT'S NOT  THE  FOR  THE  FIRST  TIME )
        else{
             anyExpiredAndRevoked = isTokenVdalid2.stream()
                    .anyMatch(t -> !t.isExpired() && !t.isRevoked());
            if(!anyExpiredAndRevoked){
                saveUserToken(user, jwtToken);
            }
            else
             revokeAllUserTokens_2(user,jwtToken);

         }



        return AuthentificationResponse.builder()

                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();




    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void saveUserToken2_true(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(true)
                .revoked(true)
                .build();
        tokenRepository.save(token);
    }
    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
         //  token.setToken(key_jwt);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void revokeAllUserTokens_2(User user,String jwtToken) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(false);
            token.setRevoked(false);
              token.setToken(jwtToken);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.userRepository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthentificationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }


}
