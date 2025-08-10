package app.global.jwt;

import app.auth.service.JwtKeyManager;
import app.auth.model.entity.KeyEntry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	private final JwtKeyManager jwtKeyManager;

	@Value("${jwt.access-token-validity-in-milliseconds}")
	private long accessTokenValidityMs;

	@Value("${jwt.refresh-token-validity-in-milliseconds}")
	private long refreshTokenValidityMs;

	@Value("${jwt.internal-token-validity-in-milliseconds}")
	private long internalTokenValidityMs;

	public String createAccessToken(String userId, List<String> roles) {
		Claims claims = Jwts.claims().subject(userId).build();
		claims.put("roles", roles);
		return createToken(claims, accessTokenValidityMs);
	}

	public String createRefreshToken() {
		Claims claims = Jwts.claims().build();
		return createToken(claims, refreshTokenValidityMs);
	}

	public String createInternalToken(String serviceName) {
		Claims claims = Jwts.claims()
			.subject(serviceName)
			.add("aud", "internal-services")
			.build();
		return createToken(claims, internalTokenValidityMs);
	}

	private String createToken(Claims claims, long validityMs) {
		Instant now = Instant.now();
		Instant validity = now.plus(validityMs, ChronoUnit.MILLIS);

		KeyEntry activeKey = jwtKeyManager.getActiveKey();
		if (activeKey == null) {
			throw new IllegalStateException("No active signing key is available.");
		}
		PrivateKey privateKey = activeKey.keyPair().getPrivate();
		String kid = activeKey.kid();

		return Jwts.builder()
			.claims(claims)
			.issuedAt(Date.from(now))
			.expiration(Date.from(validity))
			.header().keyId(kid).and()
			.signWith(privateKey, SignatureAlgorithm.RS256)
			.compact();
	}

	public Claims parseClaims(String token) {
		return Jwts.parser()
			.keyLocator(header -> {
				String kid = ((JwsHeader) header).getKeyId();
				KeyEntry keyEntry = jwtKeyManager.getKeyById(kid)
					.orElseThrow(() -> {
						log.warn("Token signed with an unknown key (kid: {})", kid);
						return new IllegalArgumentException("Token signed with an unknown key");
					});

				return keyEntry.keyPair().getPublic();
			})
			.build()
			.parseSignedClaims(token)
			.getPayload();
	}

	public boolean validateToken(String token) {
		try {
			parseClaims(token);
			return true;
		} catch (SignatureException e) {
			log.warn("Invalid JWT signature: {}", e.getMessage());
		} catch (MalformedJwtException e) {
			log.warn("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			log.warn("Expired JWT token: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			log.warn("Unsupported JWT token: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			// parseClaims의 orElseThrow에서 발생하거나, 토큰이 비어있는 경우
			log.warn("JWT claims string is empty or invalid: {}", e.getMessage());
		}
		return false;
	}

	public long getInternalTokenValidityMs() {
		return internalTokenValidityMs;
	}
}