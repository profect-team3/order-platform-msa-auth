package app.auth.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.stereotype.Component;

/**
 * RSA 키쌍과 Key ID(kid)를 생성하고 관리하는 중앙 컴포넌트입니다.
 * 애플리케이션의 생명주기 동안 키 정보를 메모리에 안전하게 보관합니다.
 */
@Component
@Getter
public class JwtKeyManager {

	private KeyPair keyPair;
	private String kid;

	/**
	 * Spring Bean이 초기화된 후, 자동으로 RSA 키쌍과 kid를 생성합니다.
	 * @PostConstruct를 사용하여 애플리케이션 시작 시 단 한 번만 실행되도록 보장합니다.
	 */
	@PostConstruct
	public void generateRsaKey() {
		this.kid = UUID.randomUUID().toString();
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			this.keyPair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Failed to generate RSA key pair", e);
		}
	}

	public RSAPublicKey getPublicKey() {
		return (RSAPublicKey) this.keyPair.getPublic();
	}

	public RSAPrivateKey getPrivateKey() {
		return (RSAPrivateKey) this.keyPair.getPrivate();
	}
}