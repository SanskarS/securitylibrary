package com.security.library.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;

public class LogoutFilter extends OncePerRequestFilter{

	@Value("${app.domain1}")
	private String domain1;
	@Value("${app.domain2}")
	private String domain2;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
	
			HttpServletRequest requesttoread = request;
			String path = requesttoread.getRequestURL().toString();
			if (path.contains("/logout")) {
				HttpServletResponse responsetowrite = (HttpServletResponse) response;
				Cookie cookie1 = new Cookie("Authorization", "");
				cookie1.setMaxAge(0);
				cookie1.setDomain(domain1);
				cookie1.setPath("/");
				Cookie cookie2 = new Cookie("Authorization", "");
				cookie2.setMaxAge(0);
				cookie2.setDomain(domain2);
				cookie2.setPath("/");
				
				responsetowrite.addCookie(cookie1);
				responsetowrite.addCookie(cookie2);
				filterChain.doFilter(request, responsetowrite);				
			}
			filterChain.doFilter(request, response);
	}

		
		
		
		


}
