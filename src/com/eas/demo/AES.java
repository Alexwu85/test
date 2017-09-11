package com.eas.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
/**
 *
 * @author Administrator
 *
 */
public class AES {
	/**  
     * 加密  
     *   
     * @param content 需要加密的内容  
     * @param password  加密密钥 
     * @return  
     */    
	private static byte[] iv1 = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
    public static String encrypt(String content, String password) {    
        try {              
            //如下代码用于根据原始的password生成加密的key，这段代码C#是没有对应的实现的  
            KeyGenerator kgen = KeyGenerator.getInstance("AES");   
//            java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");  
//            random.setSeed(password.getBytes());   
//            kgen.init(128, random);    
            SecretKey secretKey = kgen.generateKey();  
            byte[] enCodeFormat = secretKey.getEncoded();  
  
            //如下代码是标准的AES加密处理，C#可以实现  
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");  
            Cipher cipher = Cipher.getInstance("AES");          
            byte[] byteContent = content.getBytes("utf-8");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv1);
            cipher.init(Cipher.ENCRYPT_MODE, key,ivParameterSpec);
//            QEncodeUtil.base64Decode(base64Code);
//            QEncodeUtil.base64Encode(bytes);
            return QEncodeUtil.base64Encode(cipher.doFinal(byteContent));  
        } catch (Exception e) {    
//            Logger.error(e,"AES加密异常");  
        }    
        return null;  
    }   

    public static void main(String[] args) throws Exception {
        /*
         * 此处使用AES-128-ECB加密模式，key需要为16位。
         */
        String cKey = "8962201510470908";
        System.out.println(cKey.length());
        // 需要加密的字串
        String cSrc = "123456";
        System.out.println(cSrc);
        // 加密
        String encrypt = encrypt("123456", "89622015104709087435617163207900");
//        String enString = AES.Encrypt(cSrc, cKey);
        System.out.println("加密后的字串是：" + encrypt);

        // 解密
//        String DeString = AES.Decrypt(enString, cKey);
//        System.out.println("解密后的字串是：" + DeString);
    }
}