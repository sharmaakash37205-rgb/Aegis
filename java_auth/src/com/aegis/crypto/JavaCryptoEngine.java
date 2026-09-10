package com.aegis.crypto;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.function.BiConsumer;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure Java 25 implementation of Aegis Vault Streaming AES-256-GCM authenticated cipher.
 * 100% interoperable and bit-for-bit compatible with crypto_engine.py (Format Version 1).
 */
public class JavaCryptoEngine {

    public static final byte[] MAGIC_HEADER = "SECV".getBytes(); // 4-byte header
    public static final byte FORMAT_VERSION = 1;                  // Format version 1
    public static final int SALT_SIZE = 16;                       // 128-bit salt
    public static final int NONCE_SIZE = 12;                      // 96-bit nonce
    public static final int TAG_SIZE = 16;                        // 128-bit GCM tag
    public static final int ITERATIONS = 600_000;                 // 600,000 PBKDF2 iterations
    public static final int DEFAULT_CHUNK_SIZE = 64 * 1024;       // 64 KB streaming chunks

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Derives a 256-bit AES SecretKey using PBKDF2-HMAC-SHA256.
     */
    public static SecretKey deriveKey(char[] password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Key derivation failure: " + e.getMessage(), e);
        }
    }

    /**
     * Derives deterministic, unique chunk nonce by XORing chunk_index into the lower 8 bytes of base nonce.
     */
    public static byte[] getChunkNonce(byte[] baseNonce, long chunkIndex) {
        byte[] chunkNonce = new byte[NONCE_SIZE];
        System.arraycopy(baseNonce, 0, chunkNonce, 0, 4);

        ByteBuffer buf = ByteBuffer.wrap(baseNonce, 4, 8).order(ByteOrder.BIG_ENDIAN);
        long baseLow = buf.getLong();
        long chunkLow = baseLow ^ chunkIndex;

        ByteBuffer outBuf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        outBuf.putLong(chunkLow);
        System.arraycopy(outBuf.array(), 0, chunkNonce, 4, 8);

        return chunkNonce;
    }

    /**
     * Builds 17-byte Authenticated Associated Data (AAD) for chunk integrity and anti-reordering.
     */
    public static byte[] buildAad(long chunkIndex, boolean isLast) {
        ByteBuffer buf = ByteBuffer.allocate(17).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC_HEADER);       // 4 bytes
        buf.put(FORMAT_VERSION);      // 1 byte
        buf.putLong(chunkIndex);      // 8 bytes
        buf.putInt(isLast ? 1 : 0);   // 4 bytes
        return buf.array();
    }

    /**
     * Encrypts a file in 64 KB chunks using AES-256-GCM.
     */
    public static void encryptFile(File inputFile, File outputFile, char[] password, BiConsumer<Long, Long> progressCallback) throws Exception {
        long totalBytes = inputFile.length();
        byte[] salt = new byte[SALT_SIZE];
        byte[] baseNonce = new byte[NONCE_SIZE];
        SECURE_RANDOM.nextBytes(salt);
        SECURE_RANDOM.nextBytes(baseNonce);

        SecretKey key = deriveKey(password, salt, ITERATIONS);
        File tempFile = new File(outputFile.getAbsolutePath() + ".tmp");

        try (InputStream in = new BufferedInputStream(new FileInputStream(inputFile));
             OutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile))) {

            // Write 37-byte Header: MAGIC(4) + VERSION(1) + CHUNK_SIZE(4) + SALT(16) + BASE_NONCE(12)
            ByteBuffer header = ByteBuffer.allocate(37).order(ByteOrder.BIG_ENDIAN);
            header.put(MAGIC_HEADER);
            header.put(FORMAT_VERSION);
            header.putInt(DEFAULT_CHUNK_SIZE);
            header.put(salt);
            header.put(baseNonce);
            out.write(header.array());

            byte[] buffer = new byte[DEFAULT_CHUNK_SIZE];
            long bytesProcessed = 0;
            long chunkIndex = 0;

            int read = in.read(buffer);
            while (read != -1) {
                // Check if there is more data
                int nextByte = in.read();
                boolean isLast = (nextByte == -1);

                byte[] chunkData = (read == buffer.length) ? buffer : Arrays.copyOf(buffer, read);
                byte[] chunkNonce = getChunkNonce(baseNonce, chunkIndex);
                byte[] aad = buildAad(chunkIndex, isLast);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, chunkNonce);
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
                cipher.updateAAD(aad);

                byte[] ciphertext = cipher.doFinal(chunkData);
                out.write(ciphertext);

                bytesProcessed += read;
                if (progressCallback != null) {
                    progressCallback.accept(bytesProcessed, totalBytes);
                }

                if (isLast) break;

                // We read one byte to probe EOF; prepend it to next buffer
                buffer[0] = (byte) nextByte;
                int remainingRead = in.read(buffer, 1, buffer.length - 1);
                read = (remainingRead == -1) ? 1 : 1 + remainingRead;
                chunkIndex++;
            }

            out.flush();
        } catch (Exception e) {
            if (tempFile.exists()) tempFile.delete();
            throw e;
        }

        Files.move(tempFile.toPath(), outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Decrypts an encrypted file using streaming AES-256-GCM.
     */
    public static void decryptFile(File inputFile, File outputFile, char[] password, BiConsumer<Long, Long> progressCallback) throws Exception {
        long totalBytes = inputFile.length();
        File tempFile = new File(outputFile.getAbsolutePath() + ".tmp");

        try (InputStream in = new BufferedInputStream(new FileInputStream(inputFile));
             OutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile))) {

            byte[] headerBytes = in.readNBytes(37);
            if (headerBytes.length < 37) {
                throw new IllegalArgumentException("Encrypted file is too small or corrupted.");
            }

            ByteBuffer headerBuf = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN);
            byte[] magic = new byte[4];
            headerBuf.get(magic);

            if (!Arrays.equals(magic, MAGIC_HEADER)) {
                throw new IllegalArgumentException("Invalid file format. Magic header does not match SECV.");
            }

            byte version = headerBuf.get();
            if (version != FORMAT_VERSION) {
                throw new IllegalArgumentException("Unsupported vault format version: " + version);
            }

            int chunkSize = headerBuf.getInt();
            byte[] salt = new byte[SALT_SIZE];
            headerBuf.get(salt);
            byte[] baseNonce = new byte[NONCE_SIZE];
            headerBuf.get(baseNonce);

            SecretKey key = deriveKey(password, salt, ITERATIONS);
            int cipherChunkSize = chunkSize + TAG_SIZE;
            byte[] cipherBuffer = new byte[cipherChunkSize];
            long bytesProcessed = 37;
            long chunkIndex = 0;

            int read = in.read(cipherBuffer);
            while (read != -1) {
                int nextByte = in.read();
                boolean isLast = (nextByte == -1);

                byte[] encryptedChunk = (read == cipherBuffer.length) ? cipherBuffer : Arrays.copyOf(cipherBuffer, read);
                byte[] chunkNonce = getChunkNonce(baseNonce, chunkIndex);
                byte[] aad = buildAad(chunkIndex, isLast);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, chunkNonce);
                cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
                cipher.updateAAD(aad);

                byte[] decryptedChunk = cipher.doFinal(encryptedChunk);
                out.write(decryptedChunk);

                bytesProcessed += read;
                if (progressCallback != null) {
                    progressCallback.accept(bytesProcessed, totalBytes);
                }

                if (isLast) break;

                cipherBuffer[0] = (byte) nextByte;
                int remainingRead = in.read(cipherBuffer, 1, cipherBuffer.length - 1);
                read = (remainingRead == -1) ? 1 : 1 + remainingRead;
                chunkIndex++;
            }

            out.flush();
        } catch (Exception e) {
            if (tempFile.exists()) tempFile.delete();
            throw e;
        }

        Files.move(tempFile.toPath(), outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
