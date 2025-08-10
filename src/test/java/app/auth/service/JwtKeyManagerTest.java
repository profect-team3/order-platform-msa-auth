package app.auth.service;

import static org.junit.jupiter.api.Assertions.*;

import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtKeyManagerTest {

	private JwtKeyManager jwtKeyManager;

	@BeforeEach
	void setUp() {
		jwtKeyManager = new JwtKeyManager();
	}

	@Test
	@DisplayName("1. RSA 키 생성: 키 쌍이 정상적으로 생성되어야 한다")
	void shouldGenerateRsaKeyPairSuccessfully() {
		// when
		jwtKeyManager.generateRsaKey();

		// then
		assertNotNull(jwtKeyManager.getKeyPair(), "KeyPair 객체는 null이 아니어야 합니다.");
		assertNotNull(jwtKeyManager.getPublicKey(), "공개키는 null이 아니어야 합니다.");
		assertNotNull(jwtKeyManager.getPrivateKey(), "개인키는 null이 아니어야 합니다.");

		assertEquals("RSA", jwtKeyManager.getPublicKey().getAlgorithm(), "키 알고리즘은 'RSA'여야 합니다.");
		assertEquals(2048, jwtKeyManager.getPublicKey().getModulus().bitLength(), "키 길이는 2048비트여야 합니다.");
	}

	@Test
	@DisplayName("2. kid 관리: 고유한 kid가 생성되어야 한다")
	void shouldGenerateUniqueKid() {
		// when
		jwtKeyManager.generateRsaKey();

		// then
		assertNotNull(jwtKeyManager.getKid(), "kid는 null이 아니어야 합니다.");
		assertFalse(jwtKeyManager.getKid().isBlank(), "kid는 비어있지 않아야 합니다.");
	}

	@Test
	@DisplayName("3. 키 회전: 키를 다시 생성하면 kid와 키 쌍이 변경되어야 한다")
	void shouldRotateKeyAndKidOnRegeneration() {
		// given
		jwtKeyManager.generateRsaKey();
		String initialKid = jwtKeyManager.getKid();
		RSAPublicKey initialPublicKey = jwtKeyManager.getPublicKey();

		// when
		jwtKeyManager.generateRsaKey();

		// then
		assertNotEquals(initialKid, jwtKeyManager.getKid(), "새로운 kid는 이전 kid와 달라야 합니다.");
		assertNotEquals(initialPublicKey, jwtKeyManager.getPublicKey(), "새로운 공개키는 이전 공개키와 달라야 합니다.");
	}
}