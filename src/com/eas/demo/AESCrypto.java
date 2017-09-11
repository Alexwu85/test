package com.eas.demo;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
* @author babafeng
* @date : 2016年12月28日 下午2:09:05
*/
public class AESCrypto {
	private static final String SHA_MODE = "SHA-256";
	private static final String AES_MODE = "AES/ECB/PKCS5Padding";
	private static final String IV_STRING = "16-Bytes--String";
	private static byte[] iv1 = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };

	public static String encryptAES(String content, String key) 
			throws InvalidKeyException, NoSuchAlgorithmException, 
			NoSuchPaddingException, UnsupportedEncodingException, 
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

    byte[] byteContent = content.getBytes("UTF-8");

    // 注意，为了能与 iOS 统一
    // 这里的 key 不可以使用 KeyGenerator、SecureRandom、SecretKey 生成
    byte[] enCodeFormat = key.getBytes();
    SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
		
    byte[] initParam = iv1;
    IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);
		
    // 指定加密的算法、工作模式和填充方式
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
	
    byte[] encryptedBytes = cipher.doFinal(byteContent);
	
    // 同样对加密后数据进行 base64 编码
    Encoder encoder = Base64.getEncoder();
    return encoder.encodeToString(encryptedBytes);
}


	public static void main(String args[]) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final String content = "123456";
		final String key = "89622015104709087435617163207900";
		
		String enMessage = encryptAES(content, key);
//		String deMessage = decrypt(key, enMessage.trim());
//		encryptAES(content, key);
		
		System.out.println("加密密钥: " + key);
		System.out.println("加密前的内容: " + content);
		System.out.println("加密后的内容: " + enMessage);
//		System.out.println("解密后的内容: " + deMessage);
	}

}