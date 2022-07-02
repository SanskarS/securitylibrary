package com.security.library.filter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.function.BiFunction;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import com.security.library.messages.requests.RequestObjectAbstract;
import com.security.library.messages.requests.RequestObjectModel;
import com.security.library.messages.response.JwtResponse;
import com.security.library.security.CustomHeaders;
import com.security.library.security.JwtProvider;
import com.security.library.security.TaskToPerform;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthenticationFilter extends BasicAuthenticationFilter {

	public AuthenticationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	private JwtProvider jwtProvider;
	private CustomHeaders customHeaders;
	
	private Logger sl4jlogger = LoggerFactory.getLogger(AuthenticationFilter.class);
	
	@Value("${app.domain}")
	private String domain;


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		HttpServletRequest newRequest = (HttpServletRequest) request;
		RequestWrapper requesttoread = new RequestWrapper(newRequest);
		request = requesttoread;
		try {
			String path = requesttoread.getRequestURL().toString();
			if (path.contains("/public/login") && requesttoread.getMethod().equals("POST")) {
				BufferedReader reader = new BufferedReader(new InputStreamReader(requesttoread.getInputStream()));
				StringBuffer sb = new StringBuffer();
				String line = null;
				while ((line = reader.readLine()) != null) {
					sb.append(line);
				}
				String parsedReq = sb.toString();
				if (parsedReq != null) {
					String taskid = path.substring(path.indexOf("/public/"));
					sl4jlogger.info("in doFilterInternal. request path is"+taskid);
					TaskToPerform task = TaskToPerform.identifyObjectModel(taskid);
					RequestObjectModel authReq = getMappedObject(parsedReq,task.getClassObject().getClass());
					authenticateUser(authReq, request);
					
					/*
					Authentication customerdetailslogin = authenticateUser(authReq, request);
					String jwt = jwtProvider.generateJwtToken(SecurityContextHolder.getContext().getAuthentication());
					HttpServletResponse responsetowrite = (HttpServletResponse) response;
					responsetowrite.addCookie(customHeaders.prepareCookies(jwt, customerdetailslogin));
					*/
					HttpServletResponse responsetowrite = (HttpServletResponse) response;
					customHeaders.setCookies(responsetowrite);
					
					filterChain.doFilter(request, responsetowrite);
					return;
				}
			}
			
			
		} catch (Exception e) {
			sl4jlogger.debug(e.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error -> Unauthorized");
		}
		filterChain.doFilter(request, response);
	}

	private void authenticateUser(RequestObjectModel authReq,HttpServletRequest request) {

		/*
		if (jwtProvider == null) {

			ServletContext servletContext = request.getServletContext();
			WebApplicationContext webApplicationContext = WebApplicationContextUtils
					.getWebApplicationContext(servletContext);
			jwtProvider = webApplicationContext.getBean(JwtProvider.class);
		}
		*/
		if(customHeaders == null) {
			ServletContext servletContext = request.getServletContext();
			WebApplicationContext webApplicationContext = WebApplicationContextUtils
					.getWebApplicationContext(servletContext);
			customHeaders = webApplicationContext.getBean(CustomHeaders.class);
			
		}

		Authentication authentication = super.getAuthenticationManager().authenticate(
				new UsernamePasswordAuthenticationToken(authReq.getUsername(), authReq.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		

		//return authentication;
	}
	
	
	private static final BiFunction<String,Class<? extends RequestObjectAbstract>,RequestObjectModel> mapobject = (s,t) -> {
		ObjectMapper mapper = new ObjectMapper();
		try {
			return mapper.readValue(s, t);
		} catch (JsonParseException e) {
			
			e.printStackTrace();
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		return null;
	};

	public static RequestObjectModel getMappedObject(String t,Class<? extends RequestObjectAbstract> c) {
		return mapobject.apply(t, c);
	}
	
	private Cookie prepareCookies(String jwt, UserDetails customerdetailslogin) {
		JwtResponse jwtresponse = new JwtResponse(jwt, customerdetailslogin.getUsername(),
				customerdetailslogin.getAuthorities());
		String jwtto = jwtresponse.getType() + " " + jwtresponse.getToken();
		sl4jlogger.info("in Preparecookies. writting cookies");
		Cookie cookie = new Cookie("Authorization", jwtto);
		cookie.setMaxAge(-1);
		cookie.setPath("/");
		cookie.setDomain(domain);
		//cookie.setHttpOnly(true);
		return cookie;
	}
}