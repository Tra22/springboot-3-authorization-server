package com.tra21.authorization_server.constants.password_encode;

public class Argon2 {
    public static final int saltLength = 16; // salt length in bytes
    public static final int hashLength = 32; // hash length in bytes
    public static final int parallelism = 1; // currently not supported by Spring Security
    public static final int memory = 4096;   // memory costs
    public static final int iterations = 3;
}
