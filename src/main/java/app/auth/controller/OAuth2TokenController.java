package app.auth.controller;

import app.auth.service.OAuth2TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2TokenController {

	private final OAuth2TokenService oauth2TokenService;

	@PostMapping("/token")
	public ResponseEntity<Map<String, Object>> issueToken(
		@RequestHeader("Authorization") String authorizationHeader,
		@RequestParam MultiValueMap<String, String> parameters) {

		String grantType = parameters.getFirst("grant_type");

		if ("client_credentials".equals(grantType)) {
			Map<String, Object> tokenResponse = oauth2TokenService.issueTokenForClientCredentials(authorizationHeader);
			return ResponseEntity.ok(tokenResponse);
		}

		return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
	}
}
