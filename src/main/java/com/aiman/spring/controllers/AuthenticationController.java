package com.aiman.spring.controllers;

import com.aiman.spring.dtos.requests.LoginUserDto;
import com.aiman.spring.dtos.requests.RegisterUserDto;
import com.aiman.spring.dtos.responses.LoginResponse;
import com.aiman.spring.entities.User;
import com.aiman.spring.services.AuthenticationService;
import com.aiman.spring.services.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        System.out.println("Menerima request registrasi untuk email: " + registerUserDto.getEmail());
        User registeredUser = authenticationService.signup(registerUserDto);
        System.out.println("User berhasil didaftarkan: " + registeredUser.getEmail());
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
        System.out.println("Menerima request login untuk email: " + loginUserDto.getEmail());
        User authenticatedUser = authenticationService.authenticate(loginUserDto);
        System.out.println("User berhasil diautentikasi: " + authenticatedUser.getEmail());

        String jwtToken = jwtService.generateToken(authenticatedUser);
        System.out.println("Token JWT berhasil dibuat untuk user: " + authenticatedUser.getEmail());

        LoginResponse loginResponse = LoginResponse.builder()
                .token(jwtToken)
                .expiresIn(jwtService.getExpirationTime())
                .build();

        System.out.println("Respon login dikirim untuk user: " + authenticatedUser.getEmail());
        return ResponseEntity.ok(loginResponse);
    }
}