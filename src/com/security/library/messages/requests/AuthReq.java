package com.security.library.messages.requests;


public class AuthReq extends RequestObjectAbstract {

	String username;
	String password;
	String logintype;
	String ipaddress;

	public String getLogintype() {
		return logintype;
	}

	public String getIpaddress() {
		return ipaddress;
	}

	public AuthReq() {

	}

	public String getPassword() {
		return password;

	}

	public String getUsername() {
		return username;
	}

}
