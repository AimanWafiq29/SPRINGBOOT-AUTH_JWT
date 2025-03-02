package com.aiman.spring.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfiguration(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            AuthenticationProvider authenticationProvider
    ) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("Mengonfigurasi SecurityFilterChain");

        http
                .csrf(csrf -> {
                    System.out.println("Menonaktifkan CSRF");
                    csrf.disable();
                })
                .authorizeHttpRequests(auth -> {
                    System.out.println("Mengatur aturan otorisasi");
                    auth.requestMatchers("/auth/**").permitAll(); // Izinkan akses ke endpoint /auth/**
                    auth.anyRequest().authenticated(); // Semua request lainnya harus terautentikasi
                })
                .sessionManagement(session -> {
                    System.out.println("Mengatur manajemen sesi menjadi STATELESS");
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .authenticationProvider(authenticationProvider) // Tambahkan authentication provider
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // Tambahkan JWT filter

        System.out.println("Konfigurasi SecurityFilterChain selesai");
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        System.out.println("Mengonfigurasi CORS");
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(List.of("http://localhost:8005"));
        configuration.setAllowedMethods(List.of("GET", "POST"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        System.out.println("Konfigurasi CORS selesai");
        return source;
    }

}
