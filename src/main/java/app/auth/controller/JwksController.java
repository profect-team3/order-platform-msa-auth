package app.auth.controller;

import app.auth.service.JwtKeyManager;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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

	@GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String, List<Map<String, Object>>>> getJwks() {
		List<Map<String, Object>> keys = jwtKeyManager.getAllKeys().stream().map(entry -> {
			RSAPublicKey publicKey = (RSAPublicKey) entry.keyPair().getPublic();

			return Map.<String, Object>of(
				"kty", "RSA",
				"kid", entry.kid(),
				"use", "sig",
				"alg", "RS256",
				"n", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray()),
				"e", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray())
			);
		}).collect(Collectors.toList());

		Map<String, List<Map<String, Object>>> jwks = Map.of("keys", keys);

		return ResponseEntity.ok(jwks);
	}
}