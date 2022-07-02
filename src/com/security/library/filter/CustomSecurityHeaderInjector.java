package com.security.library.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.security.library.messages.response.JwtResponse;
import com.security.library.security.JwtProvider;

//@Component
public class CustomSecurityHeaderInjector extends GenericFilterBean {

	@Autowired
	private JwtProvider jwtProvider;
	private Logger sl4jlogger = LoggerFactory.getLogger(getClass());

	@Value("${app.domain1}")
	private String domain1;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterchain)
			throws IOException, ServletException {

		HttpServletRequest newRequest = (HttpServletRequest) request;
		// RequestWrapper requesttoread = new RequestWrapper(newRequest); request =
		// requesttoread;
		String path = newRequest.getRequestURL().toString();
		if ((path.contains("/public/register") || path.contains("/public/Forgot_Password_Step_3"))
				&& newRequest.getMethod().equals("POST")) {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if(!authentication.getName().equals("anonymousUser")) {
			String jwt = jwtProvider.generateJwtToken(authentication);
			HttpServletResponse responsetowrite = (HttpServletResponse) response;
			responsetowrite.addCookie(prepareCookies(jwt, authentication));
			// responsetowrite.addHeader("Authorization", jwtto);
			filterchain.doFilter(request, responsetowrite);
			}
			sl4jlogger.info("in doFilter. name of prinicipal is annonymousUser");
		}
		filterchain.doFilter(request, response);
	}

	/*
	 * private UserDetails authenticateUser(RequestObjectModel
	 * authReq,HttpServletRequest request) { if (jwtProvider == null) {
	 * 
	 * ServletContext servletContext = request.getServletContext();
	 * WebApplicationContext webApplicationContext = WebApplicationContextUtils
	 * .getWebApplicationContext(servletContext); jwtProvider =
	 * webApplicationContext.getBean(JwtProvider.class); }
	 * 
	 * Authentication authentication =
	 * super.getAuthenticationManager().authenticate( new
	 * UsernamePasswordAuthenticationToken(authReq.getUsername(),
	 * authReq.getPassword()));
	 * SecurityContextHolder.getContext().setAuthentication(authentication);
	 * 
	 * 
	 * return (UserDetails) authentication.getPrincipal(); }
	 * 
	 * 
	 * private static final BiFunction<String,Class<? extends
	 * RequestObjectAbstract>,RequestObjectModel> mapobject = (s,t) -> {
	 * ObjectMapper mapper = new ObjectMapper(); try { return mapper.readValue(s,
	 * t); } catch (JsonParseException e) {
	 * 
	 * e.printStackTrace(); } catch (IOException e) {
	 * 
	 * e.printStackTrace(); } return null; };
	 * 
	 * public static RequestObjectModel getMappedObject(String t,Class<? extends
	 * RequestObjectAbstract> c) { return mapobject.apply(t, c); }
	 */
	private Cookie prepareCookies(String jwt, Authentication customerdetailslogin) {
		sl4jlogger.info("in Preparecookies. name of prinicipal"+customerdetailslogin.getName());
		JwtResponse jwtresponse = new JwtResponse(jwt, customerdetailslogin.getName(),
				customerdetailslogin.getAuthorities());
		String jwtto = jwtresponse.getType() + " " + jwtresponse.getToken();
		sl4jlogger.info("in Preparecookies. writting cookies");
		Cookie cookie = new Cookie("Authorization", jwtto);
		cookie.setMaxAge(-1);
		cookie.setPath("/");
		cookie.setDomain(domain1);
		cookie.setHttpOnly(true);

		return cookie;
	}

}
