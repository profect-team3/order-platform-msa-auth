package app.global.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import app.auth.service.JwtKeyManager;

import java.time.Instant;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Profile("prod")
public class KmsTokenProvider implements AccessTokenProvider {

	private final KmsRsaSigner kmsSigner;           // KMS 서명기 (Config 에서 @Bean 등록)
	private final JwtKeyManager jwtKeyManager;      // kid 조회용

	@Value("${jwt.issuer}") private String issuer;
	@Value("${jwt.access-validity-seconds}") private long accessValiditySec;

	@Value("${jwt.refresh-token-validity-in-milliseconds}")
	private long refreshValidityMs;

	@Override
	public String createAccessToken(String userId, String roles) {
		Instant now = Instant.now();
		Instant exp = now.plusSeconds(accessValiditySec);

		String kid = jwtKeyManager.getActiveKid(); // 하드코딩 금지, KMS/로컬 공통

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
			.type(JOSEObjectType.JWT)
			.keyID(kid)
			.build();

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.subject(userId)
			.issuer(issuer)
			.audience("external-service")
			.issueTime(Date.from(now))
			.expirationTime(Date.from(exp))
			.claim("user_role", roles)
			.claim("token_use", "access")
			.build();

		return signAndSerialize(header, claims);
	}

	public String createRefreshToken() {
		Instant now = Instant.now();
		Instant exp = now.plusMillis(refreshValidityMs);

		String kid = jwtKeyManager.getActiveKid();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
			.type(JOSEObjectType.JWT)
			.keyID(kid)
			.build();

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer(issuer)
			.issueTime(Date.from(now))
			.expirationTime(Date.from(exp))
			.claim("token_use", "refresh")
			.build();

		return signAndSerialize(header, claims);
	}

	private String signAndSerialize(JWSHeader header, JWTClaimsSet claims) {
		try {
			SignedJWT jwt = new SignedJWT(header, claims);
			jwt.sign(kmsSigner);
			return jwt.serialize();
		} catch (JOSEException e) {
			throw new IllegalStateException("JWT sign failed", e);
		}
	}
}