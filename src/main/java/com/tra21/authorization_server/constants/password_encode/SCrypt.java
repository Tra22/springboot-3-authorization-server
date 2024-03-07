package com.tra21.authorization_server.constants.password_encode;

public class SCrypt {
    public static final int cpuCost = (int) Math.pow(2, 14); // factor to increase CPU costs
    public static final int memoryCost = 8;      // increases memory usage
    public static final int parallelization = 1; // currently not supported by Spring Security
    public static final int keyLength = 32;      // key length in bytes
    public static final int saltLength = 64;     // salt length in bytes
}
