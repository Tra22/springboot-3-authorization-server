package com.tra21.authorization_server.constants.password_encode;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

public class Pbkdf2 {
    public static final String pepper = "pepper"; // secret key used by password encoding
    public static final int iterations = 200000;  // number of hash iteration
    public static final int hashWidth = 256;
    public static final Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm DEFAULT_ALGORITHM = Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256;
}
