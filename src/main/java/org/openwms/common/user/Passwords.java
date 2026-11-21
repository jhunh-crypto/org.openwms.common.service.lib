package org.openwms.common.user;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Passwort-Hash im Format {@code pbkdf2-sha256$Iterationen$Salt$Hash} (wie im Fleet-Service).
 */
public final class Passwords {

    static final int ITERATIONS = 210_000;
    private static final int KEY_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Passwords() {
    }

    public static String hash(String secret) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(secret, salt, ITERATIONS, KEY_BITS / 8);
        return "pbkdf2-sha256$" + ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean verify(String secret, String stored) {
        if (secret == null || stored == null) {
            return false;
        }
        String[] parts = stored.split("[$]");
        if (parts.length != 4 || !"pbkdf2-sha256".equals(parts[0])) {
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] expected = Base64.getDecoder().decode(parts[3]);
        byte[] actual = derive(secret, salt, iterations, expected.length);
        return MessageDigest.isEqual(actual, expected);
    }

    private static byte[] derive(String secret, byte[] salt, int iterations, int bytes) {
        try {
            var spec = new PBEKeySpec(secret.toCharArray(), salt, iterations, bytes * 8);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 nicht verfügbar", e);
        }
    }
}
