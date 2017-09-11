package com.eas.demo;

public class Test {
public static void main(String[] args) {
	String text="89622015104709087435617163207900";
	byte[] iv1 = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };

	System.out.println(iv1.length);
}
}
