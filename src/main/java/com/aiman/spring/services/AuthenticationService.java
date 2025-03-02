package com.aiman.spring.services;

import com.aiman.spring.dtos.requests.LoginUserDto;
import com.aiman.spring.dtos.requests.RegisterUserDto;
import com.aiman.spring.entities.User;
import com.aiman.spring.repositories.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    public User signup(RegisterUserDto input) {
        System.out.println("Membuat user baru dengan email: " + input.getEmail());
        User user = User.builder()
                .fullName(input.getFullName())
                .email(input.getEmail())
                .password(passwordEncoder.encode(input.getPassword()))
                .build();

        User savedUser = userRepository.save(user);
        System.out.println("User berhasil disimpan ke database: " + savedUser.getEmail());
        return savedUser;
    }

    public User authenticate(LoginUserDto input) {
        System.out.println("Memverifikasi autentikasi user dengan email: " + input.getEmail());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );

        User user = userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> new RuntimeException("User tidak ditemukan"));
        System.out.println("User berhasil diautentikasi: " + user.getEmail());
        return user;
    }
}