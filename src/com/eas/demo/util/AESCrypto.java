package com.eas.demo.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.eas.demo.QEncodeUtil;

/**
 * This program generates a AES key, retrieves its raw bytes, and then
 * reinstantiates a AES key from the key bytes. The reinstantiated key is used
 * to initialize a AES cipher for encryption and decryption.
 */
public class AESCrypto {

    /**
     * Encrypt a sample message using AES in CBC mode with a random IV genrated
     * using SecyreRandom.
     *
     */
    public static void main(String[] args) {
        try {
            String message = "123456";
            System.out.println("Plaintext: " + message + "\n");

            // generate a key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);  // To use 256 bit keys, you need the "unlimited strength" encryption policy files from Sun.
//            byte[] key = keygen.generateKey().getEncoded();
            String key="89622015104709087435617163207900";
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");

            // build the initialization vector (randomly).
            SecureRandom random = new SecureRandom();
            byte iv[] = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };//generate random 16 byte IV AES is always 16bytes
            
            random.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // initialize the cipher for encrypt mode
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);

            System.out.println("Key: " + key + " This is important when decrypting");
            System.out.println("IV: " + new String(iv, "utf-8") + " This is important when decrypting");
            System.out.println(asHex(key.getBytes()));

            // encrypt the message
            byte[] encrypted = cipher.doFinal(message.getBytes());
            System.out.println("Ciphertext: " + QEncodeUtil.base64Encode(encrypted) + "\n");

            // reinitialize the cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);

            // decrypt the message
            byte[] decrypted = cipher.doFinal(encrypted);
            System.out.println("Plaintext: " + new String(decrypted) + "\n");
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Turns array of bytes into string
     *
     * @param buf   Array of bytes to convert to hex string
     * @return  Generated hex string
     */
    public static String asHex(byte buf[]) {
        StringBuilder strbuf = new StringBuilder(buf.length * 2);
        int i;
        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }
}