package com.polytec.security;

import java.io.Serializable;

public class Frame implements Serializable {

	// static variable for 
	// Code Description References
	// 0 Init. 
	static final byte CODE_INIT = 0;
	// 1 Request. 
	static final byte CODE_REQUEST = 1;
	// 2 Response.
	static final byte CODE_RESPONSE = 2;
	// 3 Success. 
	static final byte CODE_SUCCESS = 3;
	// 4 Failure. 
	static final byte CODE_FAILURE = 4;

	// header 
	byte code;
	byte identifier;
	int length;
	Data data;

	public String toString() {
		return "Frame {\n  code = " + code + "\n  id = " + identifier 
			+ "\n  length = " + length + "\n  data = "+ data +"\n}";
	}
	
	public Frame(){}
	
	public Frame(byte c, byte id, Data d)
	{
		code = c;
		identifier = id;
		length = d == null ? 0 : d.getLength();
		data = d;
	}
}