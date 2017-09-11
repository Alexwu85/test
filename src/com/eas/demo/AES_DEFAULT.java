package com.eas.demo;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_DEFAULT {

	public static byte[] Encrypt(SecretKey secretKey, String msg) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // : 等同 AES/ECB/PKCS5Padding
		byte[] iv = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
		// Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);
		String key="89622015104709087435617163207900";
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec,new IvParameterSpec(iv));
		System.out.println("AES_DEFAULT IV:" + cipher.getIV());
		System.out.println("AES_DEFAULT Algoritm:" + cipher.getAlgorithm());
		byte[] byteCipherText = cipher.doFinal(msg.getBytes());
		System.out.println("加密結果的Base64編碼：" + Base64.getEncoder().encodeToString(byteCipherText));
		return byteCipherText;
	}

	public static byte[] Decrypt(SecretKey secretKey, byte[] cipherText) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptedText = cipher.doFinal(cipherText);
		String strDecryptedText = new String(decryptedText);
		System.out.println("解密結果：" + strDecryptedText);
		return decryptedText;
	}

	public static void main(String args[]) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128, new SecureRandom());
		SecretKey secretKey = keyGen.generateKey();
		byte[] iv = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);

		byte[] cipher = AES_DEFAULT.Encrypt(secretKey, "123456");
		AES_DEFAULT.Decrypt(secretKey, cipher);
	}
}
