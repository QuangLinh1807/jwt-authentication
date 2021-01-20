package com.example.authentication.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenComponent {

	public static final long JWT_TOKEN_VALIDITY = 7 * 24 * 60 * 60;

	@Value("${jwt.secret}")
	private String secret;

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private boolean isTokenExpired(String token) {
		Date date = getExpirationFromToken(token);
		return date.before(new Date());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {
		Date now = new Date();
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(now)
				.setExpiration(new Date(now.getTime() + JWT_TOKEN_VALIDITY * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public String getUserNameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getExpirationFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public String generateToken(UserDetails user) {
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims, user.getUsername());
	}

	public boolean validateToken(String token, UserDetails user) {
		String userName = getUserNameFromToken(token);
		return userName.equals(user.getUsername()) && !isTokenExpired(token);
	}
}
