package com.security.library.messages.response;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;

public class JwtResponse {

	

	private String token;
	private String type = "Bearer";
	private String userName;
	
	private Collection<? extends GrantedAuthority> authorities;
	
	
	
	public JwtResponse(String jwt, String username2, Collection<? extends GrantedAuthority> authorities2) {
		this.token= jwt;
		this.userName = username2;
		this.authorities = authorities2;
		
	}



	public String getToken() {
		return token;
	}



	public void setToken(String token) {
		this.token = token;
	}



	public String getType() {
		return type;
	}



	public void setType(String type) {
		this.type = type;
	}



	public String getUserName() {
		return userName;
	}



	public void setUserName(String userName) {
		this.userName = userName;
	}



	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}



	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.authorities = authorities;
	}



	@Override
	public String toString() {
		return "JwtResponse [token=" + token + ", type=" + type + ", userName=" + userName + ", authorities="
				+ authorities + "]";
	}
	
	
	
}
