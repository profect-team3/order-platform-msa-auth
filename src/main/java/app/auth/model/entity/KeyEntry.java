package app.auth.model.entity;

import java.security.KeyPair;
import java.time.Instant;

public record KeyEntry(
	String kid,
	KeyPair keyPair,
	Instant createdAt
) {
	public KeyEntry(String kid, KeyPair keyPair) {
		this(kid, keyPair, Instant.now());
	}
}
