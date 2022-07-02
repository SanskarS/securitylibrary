package com.security.library.filter;

import java.io.IOException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;
import com.security.library.security.JwtProvider;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	JwtProvider tokenProvider;

	private Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired
	UserDetailsService customerDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		logger.info("doFilterInternal initialized");
		String jwt = getJwt(request);

		if (jwt != null && tokenProvider.validateJwtToken(jwt)) {
			logger.info("request has token");
			String mobileno = tokenProvider.getUserNameFromJwtToken(jwt);

			UserDetails userDetails = customerDetailsService.loadUserByUsername(mobileno);
			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
					null, userDetails.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authentication);
			logger.info("doFilterInternal User already Authenticated");
		}
		filterChain.doFilter(request, response);

	}

	private String getJwt(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");
		Cookie[] cookies = request.getCookies();
		String authcookievalue = new String();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("Authorization")) {
					authcookievalue = cookie.getValue();
				}
			}
		}
		if (!authcookievalue.equals("") && authcookievalue.startsWith("Bearer")) {
			return authcookievalue.replace("Bearer", "");
		}

		if (authHeader != null && authHeader.startsWith("Bearer")) {
			return authHeader.replace("Bearer", "");
		}
		return null;
	}
}
