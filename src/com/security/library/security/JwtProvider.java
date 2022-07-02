package com.security.library.security;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


@Component
public class JwtProvider {

	
	private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);
	
	@Value("${jwt.secret}")
	private String jwtSecret;
	@Value("${jwt.expire}")
	private int jwtExpiration;
	
		
	public String generateJwtToken(Authentication auth) {
		String name =auth.getName();
		Date expiration = jwtExpiration < 0 ? null : new Date((new Date()).getTime()+jwtExpiration*1000);
		return Jwts.builder().setSubject(name).setIssuedAt(new Date()).setExpiration(expiration).signWith(SignatureAlgorithm.HS512, jwtSecret).compact();		
	}
	
	
	public boolean validateJwtToken(String token) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
			return true;
		}
		catch(Exception e) {
			logger.info("Exception in Validation"+ e);
		}
		return false;
	}
	
	
	public String getUserNameFromJwtToken(String token) {		
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}
		
}
