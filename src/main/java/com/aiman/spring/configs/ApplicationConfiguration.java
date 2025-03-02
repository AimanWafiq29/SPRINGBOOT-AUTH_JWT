package com.aiman.spring.configs;

import com.aiman.spring.repositories.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    public ApplicationConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    UserDetailsService userDetailsService() {
        System.out.println("Membuat bean UserDetailsService");
        return username -> {
            System.out.println("Mencari user dengan email: " + username);
            return userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User tidak ditemukan"));
        };
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        System.out.println("Membuat bean BCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        System.out.println("Membuat bean AuthenticationManager");
        return config.getAuthenticationManager();
    }

    @Bean
    AuthenticationProvider authenticationProvider() {
        System.out.println("Membuat bean AuthenticationProvider");
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());

        System.out.println("Mengatur UserDetailsService dan PasswordEncoder di AuthenticationProvider");
        return authProvider;
    }

}
