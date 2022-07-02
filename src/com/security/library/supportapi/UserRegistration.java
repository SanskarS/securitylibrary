package com.security.library.supportapi;

import org.springframework.security.core.userdetails.UserDetails;

import com.security.library.messages.requests.RegisterForm;

public interface UserRegistration{

	UserDetails addUser(RegisterForm registerform);
}
