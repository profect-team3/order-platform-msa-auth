package app.global.jwt;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import app.auth.model.entity.KeyEntry;
import app.auth.service.JwtKeyManager;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

@Component
@Profile("!prod")
@RequiredArgsConstructor
public class LocalTokenProvider implements AccessTokenProvider{

	private final JwtKeyManager jwtKeyManager;


	@Value("${jwt.refresh-token-validity-in-milliseconds}")
	private long refreshTokenValidityMs;

	@Value("${jwt.access-token-validity-in-milliseconds}")
	private long accessTokenValidityMs;
	@Override
	public String createAccessToken(String userId, String roles) {
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
			.audience().add("external-service").and()
			.claim("user_role", roles)
			.issuedAt(Date.from(now))
			.expiration(Date.from(validity))
			.header().keyId(kid).and()
			.signWith(privateKey, Jwts.SIG.RS256)
			.compact();
	}



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

}
