package com.tra21.authorization_server.config.security;

import com.tra21.authorization_server.constants.password_encode.Argon2;
import com.tra21.authorization_server.constants.password_encode.Pbkdf2;
import com.tra21.authorization_server.constants.password_encode.SCrypt;
import com.tra21.authorization_server.services.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Configuration(value = AuthenticationProviderConfigurer.BEAN_ID)
public class AuthenticationProviderConfigurer {
    public static final String BEAN_ID = "AuthenticationProviderConfigurer@000";
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    @Bean
    PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder(SCrypt.cpuCost, SCrypt.memoryCost, SCrypt.parallelization, SCrypt.keyLength, SCrypt.saltLength));
        encoders.put("argon2", new Argon2PasswordEncoder(Argon2.saltLength, Argon2.hashLength, Argon2.parallelism, Argon2.memory, Argon2.iterations));
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder(Pbkdf2.pepper, Pbkdf2.iterations, Pbkdf2.hashWidth, Pbkdf2.DEFAULT_ALGORITHM));
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }

    @Bean
    UserDetailsService userDetailsService() {
        return customUserDetailsService;
    }
}