package com.security.library.messages.requests;

public class RegisterForm extends RequestObjectAbstract{

	private String fullname;
	private String mobileno;
	private String password;
	
	public String getFullname() {
		return fullname;
	}
	public String getMobileno() {
		return mobileno;
	}
	public String getPassword() {
		return password;
	}
	
	
	@Override
	public String getUsername() {
		
		return mobileno;
	}
	
	
}
