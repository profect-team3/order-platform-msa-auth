package app.global.jwt;

import app.auth.service.JwtKeyManager;
import app.auth.model.entity.KeyEntry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.security.PrivateKey;
import java.time.Instant;
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

	public String createRefreshToken() {
		Instant now = Instant.now();
		Instant validity = now.plusMillis(refreshTokenValidityMs);

		KeyEntry activeKey = jwtKeyManager.getActiveKey();
		if (activeKey == null) {
			throw new IllegalStateException("No active signing key is available.");
		}
		PrivateKey privateKey = activeKey.keyPair().getPrivate();
		String kid = activeKey.kid();

		return Jwts.builder()
			.issuedAt(Date.from(now))
			.expiration(Date.from(validity))
			.header().keyId(kid).and()
			.signWith(privateKey, Jwts.SIG.RS256)
			.compact();
	}


	public String createAccessToken(String userId, List<String> roles) {
		Instant now = Instant.now();
		Instant validity = now.plusMillis(accessTokenValidityMs);

		KeyEntry activeKey = jwtKeyManager.getActiveKey();
		if (activeKey == null) {
			throw new IllegalStateException("No active signing key is available.");
		}
		PrivateKey privateKey = activeKey.keyPair().getPrivate();
		String kid = activeKey.kid();

		return Jwts.builder()
			.subject(userId)
			.claim("roles", roles)
			.issuedAt(Date.from(now))
			.expiration(Date.from(validity))
			.header().keyId(kid).and()
			.signWith(privateKey, Jwts.SIG.RS256)
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
			log.warn("JWT claims string is empty or invalid: {}", e.getMessage());
		}
		return false;
	}

	public Date getExpirationDate(String token) {
		return parseClaims(token).getExpiration();
	}

	public long getInternalTokenValidityMs() {
		return internalTokenValidityMs;
	}

	public long getRefreshTokenValidityMs() {
		return refreshTokenValidityMs;
	}
}