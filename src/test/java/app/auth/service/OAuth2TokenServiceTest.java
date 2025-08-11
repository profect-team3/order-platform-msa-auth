package app.auth.service;

import app.auth.model.entity.ServiceAccount;
import app.global.jwt.JwtTokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2TokenServiceTest {

	@InjectMocks
	private OAuth2TokenService oAuth2TokenService;

	@Mock
	private ServiceAccountService serviceAccountService;

	@Mock
	private JwtTokenProvider jwtTokenProvider;

	@Test
	@DisplayName("유효한 Client Credentials로 토큰 발급 요청 시 토큰 정보를 반환해야 한다")
	void issueTokenForClientCredentials_WithValidCredentials_ShouldReturnToken() {
		// given
		String clientId = "my-service";
		String clientSecret = "my-secret";
		String serviceName = "internal-service-name";
		String credentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
		String authHeader = "Basic " + credentials;

		ServiceAccount mockAccount = new ServiceAccount(clientId, "encoded-secret", serviceName);
		String mockToken = "mock.jwt.token";
		long expiresInMs = 60000L;

		when(serviceAccountService.authenticate(clientId, clientSecret)).thenReturn(mockAccount);
		when(jwtTokenProvider.createInternalToken(serviceName)).thenReturn(mockToken);
		when(jwtTokenProvider.getInternalTokenValidityMs()).thenReturn(expiresInMs);

		// when
		Map<String, Object> tokenResponse = oAuth2TokenService.issueTokenForClientCredentials(authHeader);

		// then
		assertThat(tokenResponse).isNotNull();
		assertThat(tokenResponse.get("access_token")).isEqualTo(mockToken);
		assertThat(tokenResponse.get("token_type")).isEqualTo("Bearer");
		assertThat(tokenResponse.get("expires_in")).isEqualTo(expiresInMs / 1000);
	}

	@Test
	@DisplayName("Authorization 헤더가 없으면 IllegalArgumentException이 발생해야 한다")
	void issueToken_WithMissingHeader_ShouldThrowException() {
		// then
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Missing or invalid Basic authorization header");
	}

	@Test
	@DisplayName("Authorization 헤더 형식이 'Basic'이 아니면 IllegalArgumentException이 발생해야 한다")
	void issueToken_WithInvalidHeaderFormat_ShouldThrowException() {
		// given
		String authHeader = "Bearer some-token";

		// then
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials(authHeader))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Missing or invalid Basic authorization header");
	}

	@Test
	@DisplayName("자격 증명 인증 실패 시 ServiceAccountService의 예외가 그대로 전파되어야 한다")
	void issueToken_WhenAuthenticationFails_ShouldPropagateException() {
		// given
		String clientId = "wrong-id";
		String clientSecret = "wrong-secret";
		String credentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
		String authHeader = "Basic " + credentials;

		when(serviceAccountService.authenticate(clientId, clientSecret))
			.thenThrow(new IllegalArgumentException("Invalid credentials"));

		// then
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials(authHeader))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Invalid credentials");
	}
}