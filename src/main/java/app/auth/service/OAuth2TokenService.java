package app.auth.service;

import app.auth.model.entity.ServiceAccount;
import app.global.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OAuth2TokenService {

	private final ServiceAccountService serviceAccountService;
	private final JwtTokenProvider jwtTokenProvider;

	public Map<String, Object> issueTokenForClientCredentials(String authorizationHeader, String userId) {
		if (authorizationHeader == null || !authorizationHeader.toLowerCase().startsWith("basic ")) {
			throw new IllegalArgumentException("Missing or invalid Basic authorization header");
		}

		String base64Credentials = authorizationHeader.substring("Basic ".length()).trim();
		byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
		String credentials = new String(credDecoded);
		final String[] values = credentials.split(":", 2);
		if (values.length != 2) {
			throw new IllegalArgumentException("Invalid Basic authorization header format");
		}

		String clientId = values[0];
		String clientSecret = values[1];

		ServiceAccount account = serviceAccountService.authenticate(clientId, clientSecret);

		String accessToken = jwtTokenProvider.createInternalToken(account.getServiceName(),userId);
		long expiresIn = jwtTokenProvider.getInternalTokenValidityMs() / 1000;

		return Map.of(
			"access_token", accessToken,
			"token_type", "Bearer",
			"expires_in", expiresIn
		);
	}
}
