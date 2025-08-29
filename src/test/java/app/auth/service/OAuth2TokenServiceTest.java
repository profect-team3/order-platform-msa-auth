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
	@DisplayName("유효한 userId/userRole로 토큰 발급 요청 시 토큰 정보를 반환해야 한다")
	void issueTokenForClientCredentials_WithValidParams_ShouldReturnToken() {
		// given
		String userId = "2L";
		String userRole = "ADMIN";
		String mockToken = "mock.jwt.token";
		long expiresInMs = 60_000L;

		when(jwtTokenProvider.createInternalToken(userId, userRole)).thenReturn(mockToken);
		when(jwtTokenProvider.getInternalTokenValidityMs()).thenReturn(expiresInMs);

		// when
		Map<String, Object> tokenResponse = oAuth2TokenService.issueTokenForClientCredentials(userId, userRole);

		// then
		assertThat(tokenResponse).isNotNull();
		assertThat(tokenResponse.get("access_token")).isEqualTo(mockToken);
		assertThat(tokenResponse.get("token_type")).isEqualTo("Bearer");
		assertThat(tokenResponse.get("expires_in")).isEqualTo(expiresInMs / 1000);
	}


	@Test
	@DisplayName("userId가 없으면 IllegalArgumentException이 발생해야 한다")
	void issueToken_MissingUserId_ShouldThrowIAE() {
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials(null, "ADMIN"))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Missing required parameter: userId");
	}

	@Test
	@DisplayName("userRole이 없으면 IllegalArgumentException이 발생해야 한다")
	void issueToken_MissingUserRole_ShouldThrowIAE() {
		assertThatThrownBy(() -> oAuth2TokenService.issueTokenForClientCredentials("user123", null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Missing required parameter: userRole");
	}

}