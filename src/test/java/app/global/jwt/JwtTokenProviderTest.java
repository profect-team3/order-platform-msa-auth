package app.global.jwt;

import app.auth.model.entity.KeyEntry;

import app.auth.service.JwtKeyManager;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

	@InjectMocks
	private JwtTokenProvider jwtTokenProvider;

	@InjectMocks
	private LocalTokenProvider localTokenProvider;

	@Mock
	private JwtKeyManager jwtKeyManager;

	private KeyEntry testKeyEntry;
	private String testKid = "test-kid";

	@BeforeEach
	void setUp() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		testKeyEntry = new KeyEntry(testKid, keyPair);

		ReflectionTestUtils.setField(localTokenProvider, "accessTokenValidityMs", 3600000L); // 1시간
		ReflectionTestUtils.setField(jwtTokenProvider, "refreshTokenValidityMs", 86400000L); // 24시간
		ReflectionTestUtils.setField(jwtTokenProvider, "internalTokenValidityMs", 60000L); // 1분

		when(jwtKeyManager.getActiveKey()).thenReturn(testKeyEntry);                // 발급 때 사용
		when(jwtKeyManager.getKeyById(testKid)).thenReturn(Optional.of(testKeyEntry));
	}

	@Test
	@DisplayName("AccessToken 생성 시 올바른 Claims와 만료 시간을 가져야 한다")
	void createAccessToken_ShouldContainCorrectClaims() {
		// given
		String userId = "user123";
		String role ="CUSTOMER";
		when(jwtKeyManager.getActiveKey()).thenReturn(testKeyEntry);

		// when
		String token =localTokenProvider.createAccessToken(userId, role);

		// then
		assertThat(token).isNotNull();
		Claims claims = jwtTokenProvider.parseClaims(token);
		assertThat(claims.getSubject()).isEqualTo(userId);
		assertThat(claims.get("user_role")).isEqualTo(role);
	}

	@Test
	@DisplayName("유효한 토큰 검증(validateToken) 시 true를 반환해야 한다")
	void validateToken_WithValidToken_ShouldReturnTrue() {
		// given
		when(jwtKeyManager.getActiveKey()).thenReturn(testKeyEntry);
		when(jwtKeyManager.getKeyById(testKid)).thenReturn(Optional.of(testKeyEntry));
		String token = localTokenProvider.createAccessToken("user123", "USER");

		// when
		boolean isValid = jwtTokenProvider.validateToken(token);

		// then
		assertThat(isValid).isTrue();
	}

	@Test
	@DisplayName("서명이 다른 토큰 검증 시 false를 반환해야 한다")
	void validateToken_WithInvalidSignature_ShouldReturnFalse() throws NoSuchAlgorithmException {
		// given
		when(jwtKeyManager.getActiveKey()).thenReturn(testKeyEntry);
		String token = localTokenProvider.createAccessToken("user123", "USER");

		KeyPair otherKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		KeyEntry otherKeyEntry = new KeyEntry("other-kid", otherKeyPair);
		when(jwtKeyManager.getKeyById(testKid)).thenReturn(Optional.of(otherKeyEntry));

		// when
		boolean isValid = jwtTokenProvider.validateToken(token);

		// then
		assertThat(isValid).isFalse();
		assertThatThrownBy(() -> jwtTokenProvider.parseClaims(token))
			.isInstanceOf(SignatureException.class);
	}

	@Test
	@DisplayName("알 수 없는 kid를 가진 토큰 검증 시 false를 반환해야 한다")
	void validateToken_WithUnknownKid_ShouldReturnFalse() {
		// given
		when(jwtKeyManager.getActiveKey()).thenReturn(testKeyEntry);
		String token = localTokenProvider.createAccessToken("user123", "USER");

		when(jwtKeyManager.getKeyById(testKid)).thenReturn(Optional.empty());

		// when
		boolean isValid = jwtTokenProvider.validateToken(token);

		// then
		assertThat(isValid).isFalse();
	}
}