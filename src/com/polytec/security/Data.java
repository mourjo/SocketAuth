package com.polytec.security;

import java.io.Serializable;

public class Data implements Serializable {

	// Type
	// 0 Init
	static final byte TYPE_INIT = 0;
	// 1 Identity. 
	static final byte TYPE_IDENTITY = 1;
	// 2 Notification. 
	static final byte TYPE_NOTIFICATION = 2;
	// 3 Nak (Response only). 
	static final byte TYPE_NAK = 3;
	// 4 MD5-Challenge.  
	static final byte TYPE_MD5_CHALLENGE = 4;
	// 4 MD5-Challenge.  
	static final byte TYPE_TLS_CHALLENGE = 5;

	// type
	byte type;
	// data
	byte[] data;
	
	public Data()
	{
		
	}

	
	public Data(byte t, byte d[])
	{
		type = t;
		data = d;
	}
	
	public int getLength()
	{
		return data == null ? 0 : data.length;
	}
	
	public String toString()
	{
		String str = "<type=" + type + ", data=";
		for(byte x : data)
			str += x+" ";
		return str+">";
		
	}
}