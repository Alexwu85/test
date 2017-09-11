package com.eas.demo.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Encoder;

public class Sec {
	private static byte[] SALT_BYTES = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
	private static int ITERATION_COUNT = 19;

	
	
	public static String Encrypt(String sSrc, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");// 根据给定的字节数组构造一个密钥
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");// "算法/模式/补码方式"
        IvParameterSpec _iv = new IvParameterSpec(iv);// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, _iv);//用密钥和一组算法参数初始化此 Cipher
        byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));//按单部分操作加密或解密数据，或者结束一个多部分操作。
        return Base64.encodeBase64String(encrypted);
    }
	/**
     * 加密
     * @param content
     * @param keyBytes
     * @param iv
     * @return
     * @throws Exception
     */
    public static String AES_CBC_Encrypt(byte[] content, byte[] keyBytes, byte[] iv) throws Exception{
        try{
            KeyGenerator keyGenerator= KeyGenerator.getInstance("AES");//返回生成指定算法的密钥的 KeyGenerator 对象
            keyGenerator.init(128, new SecureRandom(keyBytes) );//使用用户提供的随机源初始化此密钥生成器，使其具有确定的密钥大小
            SecretKey key=keyGenerator.generateKey();// 生成一个密钥。
            Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] result=cipher.doFinal(content);
            return Base64.encodeBase64String(result);
        }catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
	public static void main(String[] args) throws Exception {
		byte[] iv = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
		String key="89622015104709087435617163207900";
		String d = AES_CBC_Encrypt("123456".getBytes(),key.getBytes(),iv);
		String wd = Encrypt("123456",key.getBytes(),iv);
		System.out.println(wd);
	}
}
