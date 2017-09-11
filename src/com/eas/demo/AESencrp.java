package com.eas.demo;


import java.security.AlgorithmParameters;
import java.security.Key;  
 
import javax.crypto.Cipher;  
import javax.crypto.spec.SecretKeySpec;  
 
//import sun.misc.BASE64Decoder;  
//import sun.misc.BASE64Encoder;  
 
/** 
* 用来进行AES的加密和解密程序 
*  
* @author Steven 
*  
*/  
public class AESencrp {  
 
   // 加密算法  
   private String ALGO;  
 
   // 加密密钥  
   // private static final byte[] keyValue = new byte[] { 'T', 'h', 'e',  
   // 'B','e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };  
   // 16位的加密密钥  
   private byte[] keyValue;  
 
   /** 
    * 用来进行加密的操作 
    *  
    * @param Data 
    * @return 
    * @throws Exception 
    */  
   public String encrypt(String Data) throws Exception {  
       Key key = generateKey();  
       Cipher c = Cipher.getInstance(ALGO);
       c.init(Cipher.ENCRYPT_MODE, key);
       
       byte[] iv = c.getIV();
//       int blockSize = c.getBlockSize();
//       AlgorithmParameters parameters = c.getParameters();
//       System.out.println(parameters);

       byte[] encVal = c.doFinal(Data.getBytes());  
       String encryptedValue = QEncodeUtil.base64Encode(encVal);  
       return encryptedValue;  
   }  
 
   /** 
    * 用来进行解密的操作 
    *  
    * @param encryptedData 
    * @return 
    * @throws Exception 
    */  
   public String decrypt(String encryptedData) throws Exception {  
       Key key = generateKey();  
       Cipher c = Cipher.getInstance(ALGO);  
       c.init(Cipher.DECRYPT_MODE, key);  
       byte[] decordedValue = QEncodeUtil.base64Decode(encryptedData);  
       byte[] decValue = c.doFinal(decordedValue);  
       String decryptedValue = new String(decValue);  
       return decryptedValue;  
   }  
 
   /** 
    * 根据密钥和算法生成Key 
    *  
    * @return 
    * @throws Exception 
    */  
   private Key generateKey() throws Exception {  
       Key key = new SecretKeySpec(keyValue, ALGO);  
       return key;  
   }  
 
   public String getALGO() {  
       return ALGO;  
   }  
 
   public void setALGO(String aLGO) {  
       ALGO = aLGO;  
   }  
 
   public byte[] getKeyValue() {  
       return keyValue;  
   }  
 
   public void setKeyValue(byte[] keyValue) {  
       this.keyValue = keyValue;  
   } 
   public static void main(String[] args) throws Exception {
	   byte[] iv1 = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
	   // 创建加解密  
       AESencrp aes = new AESencrp();  
       // 设置加解密算法  
       aes.setALGO("AES");
       // 设置加解密密钥  
       aes.setKeyValue(iv1);  
      System.out.println( aes.generateKey().getAlgorithm());;
       // 要进行加密的密码  
       String password = "123456";  
       // 进行加密后的字符串  
       String passwordEnc = aes.encrypt(password);  
       String passwordDec = aes.decrypt(passwordEnc);  
       System.out.println("原来的密码 : " + password);  
       System.out.println("加密后的密码 : " + passwordEnc);  
       System.out.println("解密后的原密码 : " + passwordDec); 
}
}