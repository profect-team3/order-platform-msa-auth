package app.auth.controller;

import app.auth.service.OAuth2TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2TokenController {

	private final OAuth2TokenService oauth2TokenService;

	@PostMapping(
		value = "/token",
		consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
		produces = MediaType.APPLICATION_JSON_VALUE
	)
	public ResponseEntity<Map<String, Object>> issueToken(
		@RequestParam MultiValueMap<String, String> parameters) {

		String grantType = parameters.getFirst("grant_type");
		if (!"client_credentials".equals(grantType)) {
			return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
		}


		String userId = parameters.getFirst("user_id");
		String userRole = parameters.getFirst("user_role");
		Map<String, Object> tokenResponse =
			oauth2TokenService.issueTokenForClientCredentials(userId,userRole);

		return ResponseEntity.ok(tokenResponse);
	}
}