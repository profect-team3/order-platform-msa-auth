package app.auth.service;

import app.global.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class OAuth2TokenService {

	private final JwtTokenProvider jwtTokenProvider;

	public Map<String, Object> issueTokenForClientCredentials(String userId,String userRole) {
		if (userId == null || userId.isBlank()) {
			throw new IllegalArgumentException("Missing required parameter: userId");
		}
		if (userRole == null || userRole.isBlank()) {
			throw new IllegalArgumentException("Missing required parameter: userRole");
		}

		String accessToken = jwtTokenProvider.createInternalToken(userId,userRole);
		long expiresIn = jwtTokenProvider.getInternalTokenValidityMs() / 1000;

		return Map.of(
			"access_token", accessToken,
			"token_type", "Bearer",
			"expires_in", expiresIn
		);
	}
}
