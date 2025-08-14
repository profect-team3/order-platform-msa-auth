package app.auth.service;

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
		String userId="2L";

		String mockToken = "mock.jwt.token";
		long expiresInMs = 60000L;


		when(jwtTokenProvider.createInternalToken(serviceName,userId)).thenReturn(mockToken);
		when(jwtTokenProvider.getInternalTokenValidityMs()).thenReturn(expiresInMs);

		// when
		Map<String, Object> tokenResponse = oAuth2TokenService.issueTokenForClientCredentials(authHeader,userId);

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
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials(null,null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Missing or invalid Basic authorization header");
	}

	@Test
	@DisplayName("Authorization 헤더 형식이 'Basic'이 아니면 IllegalArgumentException이 발생해야 한다")
	void issueToken_WithInvalidHeaderFormat_ShouldThrowException() {
		// given
		String authHeader = "Bearer some-token";
		String userId="2L";

		// then
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials(authHeader,userId))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Missing or invalid Basic authorization header");
	}

}