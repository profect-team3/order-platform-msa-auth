package app.auth.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.annotation.PostConstruct;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class JwtKeyManager {

	private final Map<String, KeyEntry> keys = new ConcurrentHashMap<>();
	private volatile String activeKid;

	@PostConstruct
	public void init() {
		rotateKey();
	}

	public KeyEntry rotateKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			String kid = UUID.randomUUID().toString();
			KeyEntry newKey = new KeyEntry(kid, keyPair, Instant.now());

			this.keys.put(kid, newKey);
			this.activeKid = kid;

			return newKey;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("RSA 키 생성에 실패", e);
		}
	}

	public KeyEntry getActiveKey() {
		return keys.get(activeKid);
	}

	public Optional<KeyEntry> getKeyById(String kid) {
		return Optional.ofNullable(keys.get(kid));
	}

	public Collection<KeyEntry> getAllKeys() {
		return keys.values();
	}

	/**
	 * 스케줄러 사용, 매 자정마다 실행
	 */
	@Scheduled(cron = "0 0 0 * * ?")
	public void removeOldKeys() {
		Instant cutoff = Instant.now().minus(Duration.ofDays(7));
		keys.entrySet().removeIf(entry ->
			!entry.getKey().equals(activeKid) && entry.getValue().createdAt().isBefore(cutoff)
		);}
}