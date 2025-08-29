package app.global.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtIssueService {
	private final JWSSigner kmsSigner;

	@Value("${jwt.issuer}") private String issuer;
	@Value("${jwt.access-validity-seconds}") private long validitySec;
	@Value("${kms.jwt.key-id}") private String kid;

	public String issueAccessToken(String userId, List<String> roles) {
		Instant now = Instant.now();
		Instant exp = now.plusSeconds(validitySec);

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
			.claim("roles", roles)
			.build();


		SignedJWT jwt = new SignedJWT(header, claims);
		try {
			jwt.sign(kmsSigner);
			return jwt.serialize();
		} catch (JOSEException e) {
			throw new IllegalStateException("JWT sign failed", e);
		}
	}
}