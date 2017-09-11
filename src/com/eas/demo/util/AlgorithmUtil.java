package com.eas.demo.util;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.eas.demo.QEncodeUtil;

/** * 算法工具 * @author Babylon 214750838@qq.com * @date 2014-8-15 上午8:41:49 */
public class AlgorithmUtil{

    public final static String ENCODING = "UTF-8";

    /**将二进制转换成16进制 * @param buf * @return */   
     public static String parseByte2HexStr(byte buf[]) {  
             StringBuffer sb = new StringBuffer();   
             for (int i = 0; i < buf.length; i++) {   
                     String hex = Integer.toHexString(buf[i] & 0xFF);   
                     if (hex.length() == 1) {   
                             hex = '0' + hex;   
                     }   
                     sb.append(hex.toUpperCase());   
             }   
             return sb.toString();   
     }

     /**将16进制转换为二进制 * @param hexStr * @return */   
      public static byte[] parseHexStr2Byte(String hexStr) {   
              if (hexStr.length() < 1)   
                      return null;   
              byte[] result = new byte[hexStr.length()/2];   
              for (int i = 0;i< hexStr.length()/2; i++) {   
                      int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);   
                      int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);   
                      result[i] = (byte) (high * 16 + low);   
              }   
              return result;   
      }   

     /** * 生成密钥 * 自动生成base64 编码后的AES128位密钥 * @throws NoSuchAlgorithmException * @throws UnsupportedEncodingException */  
    public static String getAESKey() throws Exception {
    	byte[] iv1 = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
        String k="89622015104709087435617163207900";
    	KeyGenerator kg = KeyGenerator.getInstance("AES");  
        kg.init(128);//要生成多少位，只需要修改这里即可128, 192或256 
        SecretKey sk = kg.generateKey();
        byte[] b = sk.getEncoded();
        return parseByte2HexStr(iv1);
    }  

    /** * AES 加密 * 
     * @param base64Key base64编码后的 AES key 
     * @param text 待加密的字符串 
	 * @return 加密后的byte[] 数组 
	 * @throws Exception */
    public static byte[] getAESEncode(String base64Key, String text) throws Exception{  
        byte[] key = parseHexStr2Byte(base64Key);
        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");  
        Cipher cipher = Cipher.getInstance("AES");  
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec);  
        byte[] bjiamihou = cipher.doFinal(text.getBytes(ENCODING));  
        return bjiamihou;  
    }  

    /** * AES解密 * @param base64Key base64编码后的 AES key * @param text 待解密的字符串 * @return 解密后的byte[] 数组 * @throws Exception */
    public static byte[] getAESDecode(String base64Key, byte[] text) throws Exception{  
        byte[] key = parseHexStr2Byte(base64Key);
        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");  
        Cipher cipher = Cipher.getInstance("AES");  
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec);  
        byte[] bjiemihou = cipher.doFinal(text);  
        return bjiemihou;
    }  
    public static void main(String[] args) throws Exception {
    	byte[] iv1 = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
        String k="89622015104709087435617163207900";
        
        System.out.println(new String(iv1));
        
    	String encrypt = AES_CBC_Encrypt("123456".getBytes(), k.getBytes(), iv1);
    	System.out.println(encrypt);
        /*try {
            String hexKey = new AlgorithmUtil().getAESKey();
            System.out.println("16进制秘钥："+hexKey);
            byte[] encoded = AlgorithmUtil.getAESEncode(hexKey, "123456");
            System.out.println(QEncodeUtil.base64Encode(encoded));
            // 注意，这里的encoded是不能强转成string类型字符串的
            byte[] decoded = AlgorithmUtil.getAESDecode(hexKey, encoded);
            System.out.println(new String(decoded, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }*/
    }
    /**
     * 提供密钥和向量进行加密
     *
     * @param sSrc
     * @param key
     * @param iv
     * @return
     * @throws Exception
     */
    private static String key="144831ab75bf78c6";
    private static     String algorithm = "AES/ECB/PKCS7Padding";  
    public static String Encrypt(String sSrc, byte[] key, byte[] iv) throws Exception {
    	Cipher c = Cipher.getInstance("AES");
    	SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    	c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
    	
    	
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
        	
        	
            KeyGenerator keyGenerator= KeyGenerator.getInstance("AES");//返回生成指定算法的秘密密钥的 KeyGenerator 对象
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
}
