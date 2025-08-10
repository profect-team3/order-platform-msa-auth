package app.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import app.auth.service.JwtKeyManager;
import app.auth.service.KeyEntry;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("JwtKeyManager 단위 테스트")
class JwtKeyManagerTest {

	private JwtKeyManager jwtKeyManager;

	@BeforeEach
	void setUp() {
		jwtKeyManager = new JwtKeyManager();
	}

	@Nested
	@DisplayName("초기화 및 첫 키 생성")
	class InitialKeyGeneration {

		@Test
		@DisplayName("init() 호출 시, 활성 키가 1개 생성되어야 한다")
		void shouldCreateOneActiveKeyOnInit() {
			// when
			jwtKeyManager.init();

			// then
			KeyEntry activeKey = jwtKeyManager.getActiveKey();
			assertNotNull(activeKey, "활성 키는 null이 아니어야 합니다.");
			assertThat(activeKey.kid()).isNotBlank();
			assertThat(activeKey.keyPair()).isNotNull();

			RSAPublicKey publicKey = (RSAPublicKey) activeKey.keyPair().getPublic();
			assertEquals("RSA", publicKey.getAlgorithm());
			assertEquals(2048, publicKey.getModulus().bitLength());

			assertThat(jwtKeyManager.getAllKeys()).hasSize(1);
			assertThat(jwtKeyManager.getAllKeys()).containsExactly(activeKey);
		}
	}

	@Nested
	@DisplayName("키 회전 (Key Rotation)")
	class KeyRotation {

		private KeyEntry initialKey;

		@BeforeEach
		void generateInitialKey() {
			jwtKeyManager.init();
			initialKey = jwtKeyManager.getActiveKey();
		}

		@Test
		@DisplayName("rotateKey() 호출 시, 새로운 활성 키가 생성되고 기존 키는 유지되어야 한다")
		void shouldGenerateNewActiveKeyAndKeepOldKey() {
			// when
			jwtKeyManager.rotateKey();

			// then
			KeyEntry newActiveKey = jwtKeyManager.getActiveKey();

			assertNotNull(newActiveKey);
			assertNotEquals(initialKey.kid(), newActiveKey.kid(), "새로운 활성 키의 kid는 이전과 달라야 합니다.");
			assertNotEquals(initialKey.keyPair().getPublic(), newActiveKey.keyPair().getPublic(), "새로운 공개키는 이전과 달라야 합니다.");

			assertThat(jwtKeyManager.getAllKeys()).hasSize(2);
			assertThat(jwtKeyManager.getAllKeys()).contains(initialKey, newActiveKey);

			assertThat(jwtKeyManager.getKeyById(initialKey.kid())).hasValue(initialKey);
		}
	}

	@Nested
	@DisplayName("키 조회")
	class KeyRetrieval {

		@BeforeEach
		void generateKeys() {
			jwtKeyManager.init();
			jwtKeyManager.rotateKey();
		}

		@Test
		@DisplayName("getAllKeys()는 모든 생성된 키를 반환해야 한다")
		void shouldReturnAllGeneratedKeys() {
			// then
			assertThat(jwtKeyManager.getAllKeys()).hasSize(2);
		}

		@Test
		@DisplayName("getKeyById()는 정확한 kid로 키를 찾아야 한다")
		void shouldFindKeyByCorrectKid() {
			// given
			KeyEntry activeKey = jwtKeyManager.getActiveKey();
			String activeKid = activeKey.kid();

			// when
			var foundKey = jwtKeyManager.getKeyById(activeKid);

			// then
			assertThat(foundKey).hasValue(activeKey);
		}

		@Test
		@DisplayName("getKeyById()는 존재하지 않는 kid에 대해 empty를 반환해야 한다")
		void shouldReturnEmptyForNonExistentKid() {
			// when
			var foundKey = jwtKeyManager.getKeyById("non-existent-kid");

			// then
			assertThat(foundKey).isEmpty();
		}
	}
}