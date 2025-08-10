package app.global.jwt;

import app.auth.service.JwtKeyManager;
import app.auth.service.KeyEntry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	private final JwtKeyManager jwtKeyManager;

	@Value("${jwt.access-token-validity-in-milliseconds}")
	private long accessTokenValidityInMilliseconds;

	public String createAccessToken(String userId) {
		Claims claims = Jwts.claims().subject(userId).build();

		Instant now = Instant.now();
		Instant validity = now.plus(accessTokenValidityInMilliseconds, ChronoUnit.MILLIS);

		KeyEntry activeKey = jwtKeyManager.getActiveKey();
		if (activeKey == null) {
			throw new IllegalStateException("No active signing key is available.");
		}
		PrivateKey privateKey = activeKey.keyPair().getPrivate();
		String kid = activeKey.kid();

		return Jwts.builder()
			.claims(claims)
			.issuedAt(java.util.Date.from(now))
			.expiration(java.util.Date.from(validity))
			.header().keyId(kid).and()
			.signWith(privateKey, SignatureAlgorithm.RS256)
			.compact();
	}
}