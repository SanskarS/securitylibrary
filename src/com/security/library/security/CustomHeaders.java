package com.security.library.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import com.security.library.messages.response.JwtResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class CustomHeaders {

	//@Autowired
	private final JwtProvider jwtProvider;
	
	@Value("${app.domain}")
	private String domain;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CustomHeaders.class);
	
	
	public CustomHeaders(JwtProvider jwtProvider) {
		this.jwtProvider = jwtProvider;
	}
	
	public void setCookies(HttpServletResponse response) {	
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String jwt = jwtProvider.generateJwtToken(authentication);
		response.addCookie(prepareCookies(jwt, authentication));		
	}
	
	
	private Cookie prepareCookies(String jwt, Authentication customerdetailslogin) {
		LOGGER.info("in Preparecookies. name of prinicipal {}",customerdetailslogin.getName());
		JwtResponse jwtresponse = new JwtResponse(jwt, customerdetailslogin.getName(),
				customerdetailslogin.getAuthorities());
		String jwtto = jwtresponse.getType() + " " + jwtresponse.getToken();
		LOGGER.info("in Preparecookies. writting cookies");
		Cookie cookie = new Cookie("Authorization", jwtto);
		cookie.setMaxAge(-1);
		cookie.setPath("/");
		cookie.setDomain(domain);
		//cookie.setHttpOnly(true);

		return cookie;
	}

}
