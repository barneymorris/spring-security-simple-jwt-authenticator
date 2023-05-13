package com.barney.jwtauthenticator.controllers;

import com.barney.jwtauthenticator.dto.UserLoginDTO;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.util.Base64;

@RestController
public class LoginController {

    private final AuthenticationManager authenticationManager;

    public LoginController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserLoginDTO userLoginDTO) {

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userLoginDTO.getUsername(), userLoginDTO.getPassword());
        authenticationManager.authenticate(token);

        String secret = "bly6gyyxmwy7aisffbcmq5gb9x30n1prsyjnp9e4dbcmma0n53ptb91l9krw41eb";
        Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(secret),
                SignatureAlgorithm.HS256.getJcaName());

        String jws = Jwts.builder()
                .setIssuer("barney")
                .setSubject(userLoginDTO.getUsername())
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(60*60*24)))
                .signWith(hmacKey)
                .compact();

        return new ResponseEntity<>(jws, HttpStatus.OK);
    }
}
