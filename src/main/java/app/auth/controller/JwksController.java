package app.auth.controller;

import app.auth.service.JwtKeyManager;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class JwksController {

	private final JwtKeyManager jwtKeyManager;

	/**
	 * 현재 서버가 보유한 공개키 목록을 JWKS 형식으로 반환합니다.
	 * 클라이언트는 이 정보를 캐싱하여 JWT 검증 시 활용할 수 있습니다.
	 * @return JWKS 형식의 JSON 데이터
	 */
	@GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String, List<Map<String, Object>>>> getJwks() {
		RSAPublicKey publicKey = jwtKeyManager.getPublicKey();

		Map<String, Object> jwk = Map.of(
			"kty", "RSA",
			"kid", jwtKeyManager.getKid(),
			"use", "sig",
			"alg", "RS256",
			"n", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray()),
			"e", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray())
		);

		Map<String, List<Map<String, Object>>> jwks = Map.of("keys", List.of(jwk));

		return ResponseEntity.ok(jwks);
	}
}