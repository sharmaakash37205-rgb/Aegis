package com.aegis.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Enterprise-grade password hashing service utilizing PBKDF2-HMAC-SHA256
 * with 600,000 iterations and cryptographically secure 128-bit salts.
 */
public class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int ITERATIONS = 600_000; // OWASP recommendation
    public static final int KEY_LENGTH = 256;      // 256-bit key
    public static final int SALT_SIZE = 16;        // 128-bit salt
    public static final int MAX_PASSWORD_LENGTH = 128; // OWASP recommendation to mitigate PBKDF2 DoS

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static class HashResult {
        private final String hashBase64;
        private final String saltBase64;
        private final int iterations;

        public HashResult(String hashBase64, String saltBase64, int iterations) {
            this.hashBase64 = hashBase64;
            this.saltBase64 = saltBase64;
            this.iterations = iterations;
        }

        public String getHashBase64() {
            return hashBase64;
        }

        public String getSaltBase64() {
            return saltBase64;
        }

        public int getIterations() {
            return iterations;
        }
    }

    /**
     * Generates a cryptographically secure random salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes a password with a newly generated random salt.
     */
    public static HashResult hashPassword(char[] password) {
        byte[] salt = generateSalt();
        byte[] hash = computeHash(password, salt, ITERATIONS);
        return new HashResult(
            Base64.getEncoder().encodeToString(hash),
            Base64.getEncoder().encodeToString(salt),
            ITERATIONS
        );
    }

    /**
     * Hashes a password with an existing base64-encoded salt and iteration count.
     */
    public static String hashWithSalt(char[] password, String saltBase64, int iterations) {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        byte[] hash = computeHash(password, salt, iterations);
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Verifies a candidate password against an expected base64 hash using constant-time comparison.
     */
    public static boolean verifyPassword(char[] candidatePassword, String expectedHashBase64, String saltBase64, int iterations) {
        if (candidatePassword == null || candidatePassword.length == 0 || candidatePassword.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        try {
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            byte[] expectedHash = Base64.getDecoder().decode(expectedHashBase64);
            byte[] actualHash = computeHash(candidatePassword, salt, iterations);

            // Constant-time comparison to prevent timing side-channel attacks
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] computeHash(char[] password, byte[] salt, int iterations) {
        if (password != null && password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password exceeds maximum allowed length of " + MAX_PASSWORD_LENGTH + " characters.");
        }
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Cryptographic algorithm error: " + e.getMessage(), e);
        }
    }

    /**
     * Validates password strength (minimum 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char).
     */
    public static String checkPasswordStrength(String password) {
        if (password == null || password.length() < 8) {
            return "Password must be at least 8 characters long.";
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            return "Password must not exceed " + MAX_PASSWORD_LENGTH + " characters.";
        }
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        if (!hasUpper) return "Password must contain at least one uppercase letter.";
        if (!hasLower) return "Password must contain at least one lowercase letter.";
        if (!hasDigit) return "Password must contain at least one numeric digit.";
        if (!hasSpecial) return "Password must contain at least one special character.";

        return null; // Valid
    }
}
