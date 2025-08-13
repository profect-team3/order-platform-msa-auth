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
	public ResponseEntity<Map<String, List<Map<String, Object>>>> jwks() {
		return ResponseEntity.ok(buildJwks());
	}

	private Map<String, List<Map<String, Object>>> buildJwks() {
		List<Map<String, Object>> keys = jwtKeyManager.getAllKeys().stream()
			.map(entry -> {
				RSAPublicKey pub = (RSAPublicKey) entry.keyPair().getPublic();

				byte[] nBytes = stripLeadingZero(pub.getModulus().toByteArray());
				byte[] eBytes = stripLeadingZero(pub.getPublicExponent().toByteArray());

				String n = Base64.getUrlEncoder().withoutPadding().encodeToString(nBytes);
				String e = Base64.getUrlEncoder().withoutPadding().encodeToString(eBytes);

				return Map.<String, Object>of(
					"kty", "RSA",
					"kid", entry.kid(),
					"use", "sig",
					"alg", "RS256",
					"n", n,
					"e", e
				);
			})
			.collect(Collectors.toList());

		return Map.of("keys", keys);
	}

	private static byte[] stripLeadingZero(byte[] bytes) {
		if (bytes.length > 1 && bytes[0] == 0x00) {
			byte[] copy = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, copy, 0, copy.length);
			return copy;
		}
		return bytes;
	}

}