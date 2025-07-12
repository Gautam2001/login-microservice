package com.Login.Utility.Security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.Login.Utility.AppException;
import com.Login.Utility.CommonUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	private final PrivateKey privateKey;
	private final PublicKey publicKey;

	private final long ACCESS_TOKEN_EXPIRY = 1000 * 60 * 15; // 15 min
	private final long REFRESH_TOKEN_EXPIRY = 1000L * 60 * 60 * 24 * 1; // 1 days

	public JwtUtil() throws Exception {
		super();
		this.privateKey = RsaKeyUtil.loadPrivateKey();
		this.publicKey = RsaKeyUtil.loadPublicKey();
	}

	public String generateToken(String subject, String role, String tokenType, long expiry) {
		CommonUtils.logMethodEntry(this);
		return Jwts.builder().setSubject(subject).claim("role", role).claim("type", tokenType) // "access" or "refresh"
				.setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + expiry))
				.signWith(privateKey, SignatureAlgorithm.RS256).compact();
	}

	public String generateAccessToken(String username, String role) {
		return generateToken(username, role, "access", ACCESS_TOKEN_EXPIRY);
	}

	public String generateRefreshToken(String username, String role) {
		return generateToken(username, role, "refresh", REFRESH_TOKEN_EXPIRY);
	}

	public Claims validateToken(String token, String expectedType) {
		CommonUtils.logMethodEntry(this);
		Claims claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token).getBody();

		String actualType = (String) claims.get("type");
		if (!expectedType.equals(actualType)) {
			throw new AppException("Invalid token type", HttpStatus.UNAUTHORIZED);

		}
		return claims;
	}

}
