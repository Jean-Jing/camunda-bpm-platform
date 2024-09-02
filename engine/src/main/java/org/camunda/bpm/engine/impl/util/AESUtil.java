package org.camunda.bpm.engine.impl.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

    private static final String AES = "AES";
    private static final String AES_GCM_NO_PADDING = "AES/CBC/PKCS5Padding";

    private static final String COMMON_ENCRYPT_KEY_IV = System.getenv("COMM_ENCRYPT_KEY_IV");

    private static final String ENCRYPT_KEY = COMMON_ENCRYPT_KEY_IV.substring(0, 64);
    private static final String ENCRYPT_IV = COMMON_ENCRYPT_KEY_IV.substring(65, 97);

    public static String encrypt(String plainText) throws Exception {
        byte[] keyBytes = stringToByteArray(ENCRYPT_KEY);
        byte[] ivBytes = stringToByteArray(ENCRYPT_IV);

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, AES);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] inputBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {

        System.out.println("key: " + ENCRYPT_KEY);
        System.out.println("IV: " + ENCRYPT_IV);

        if (encryptedText == null || !encryptedText.startsWith("ENC(") || !encryptedText.endsWith(")")) {
            return "";
        }

        String encryptedVal = encryptedText.substring(4, encryptedText.length() - 1);

        System.out.println("Encrypted Value: " + encryptedVal);

        byte[] keyBytes = stringToByteArray(ENCRYPT_KEY);
        byte[] ivBytes = stringToByteArray(ENCRYPT_IV);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedVal);

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, AES);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] stringToByteArray(String hex) {
        int length = hex.length();
        byte[] bytes = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, 2 + i), 16);
        }

        return bytes;
    }
}
