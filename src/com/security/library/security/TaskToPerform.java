package com.security.library.security;


import com.security.library.messages.requests.AuthReq;
import com.security.library.messages.requests.RegisterForm;
import com.security.library.messages.requests.RequestObjectAbstract;


public enum TaskToPerform {

	
	LOGIN("/public/login",new AuthReq()),
	REGISTER("/public/register",new RegisterForm()),
	FORGOT_PASSWORD3("/public/Forgot_Password_Step_3",new AuthReq());

	private String path;
	private RequestObjectAbstract classobject;
		
	private TaskToPerform(String path,RequestObjectAbstract classobject) {
		this.path = path;
		this.classobject = classobject;
	}

	
	public RequestObjectAbstract getClassObject() {
		return classobject;
	}
	
	public static TaskToPerform/*RequestObjectAbstract*/ identifyObjectModel(String path) {
		for(TaskToPerform s : values()) {
			if(s.path.equals(path)) {
				return s;
			}
		}
		return null;
	}
	
	
}
