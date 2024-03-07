package com.tra21.authorization_server.utils;

import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.util.ResourceUtils;

import java.io.FileReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

public final class JwksUtil {

    private JwksUtil() {
    }

    public static RSAKey buildDefaultRsaKey() {
        // @formatter:off
        return new RSAKey
                .Builder(readPublicKey())
                .privateKey(readPrivateKey())
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }

    public static RSAPublicKey readPublicKey() {

        try (FileReader keyReader = new FileReader(ResourceUtils.getFile("classpath:keys/public.key"));
             PemReader pemReader = new PemReader(keyReader)) {

            KeyFactory factory = KeyFactory.getInstance("RSA");
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            return (RSAPublicKey) factory.generatePublic(pubKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Cannot read public key", e);
        }
    }

    public static RSAPrivateKey readPrivateKey() {
        try (FileReader keyReader = new FileReader(ResourceUtils.getFile("classpath:keys/private.key"));
             PemReader pemReader = new PemReader(keyReader)) {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Cannot read private key", e);
        }
    }
}