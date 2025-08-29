package app.auth.service;

import app.auth.model.entity.RefreshToken;
import app.auth.model.repository.RefreshTokenRepository;
import app.global.jwt.JwtTokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

	@InjectMocks
	private RefreshTokenService refreshTokenService;

	@Mock
	private RefreshTokenRepository refreshTokenRepository;

	@Mock
	private JwtTokenProvider jwtTokenProvider;

	@Mock
	private RedisTemplate<String, String> redisTemplate;

	@Mock
	private SetOperations<String, String> setOperations;

	@Test
	@DisplayName("Refresh Token 생성 시 Redis에 토큰과 사용자 인덱스가 저장되어야 한다")
	void createRefreshToken_ShouldSaveTokenAndUserIndex() {
		// given
		String userId = "user123";
		long validityMs = 604800000L;
		long ttlInSeconds = 604800;

		when(jwtTokenProvider.getRefreshTokenValidityMs()).thenReturn(validityMs);
		when(redisTemplate.opsForSet()).thenReturn(setOperations);

		// when
		String createdToken = refreshTokenService.createRefreshToken(userId);

		// then
		assertThat(createdToken).isNotNull();
		verify(refreshTokenRepository).save(any(RefreshToken.class));
		String expectedUserTokensKey = "user_tokens:" + userId;
		verify(setOperations).add(eq(expectedUserTokensKey), eq(createdToken));
		verify(redisTemplate).expire(eq(expectedUserTokensKey), eq(ttlInSeconds), eq(TimeUnit.SECONDS));
	}

	@Test
	@DisplayName("유효한 토큰으로 검증 및 회전 시, 토큰을 삭제하고 사용자 ID를 반환해야 한다")
	void validateAndRotate_WithValidToken_ShouldDeleteTokenAndReturnUserId() {
		// given
		String userId = "user123";
		String token = "valid-token";
		RefreshToken foundToken = new RefreshToken(token, userId, 3600L);

		when(refreshTokenRepository.findById(token)).thenReturn(Optional.of(foundToken));
		when(redisTemplate.opsForSet()).thenReturn(setOperations);

		// when
		Optional<String> resultUserId = refreshTokenService.validateAndRotate(token);

		// then
		assertThat(resultUserId).isPresent().contains(userId);
		verify(refreshTokenRepository).delete(foundToken);
		String expectedUserTokensKey = "user_tokens:" + userId;
		verify(setOperations).remove(eq(expectedUserTokensKey), eq(token));
	}

	@Test
	@DisplayName("유효하지 않은 토큰으로 검증 시, 빈 Optional을 반환해야 한다")
	void validateAndRotate_WithInvalidToken_ShouldReturnEmpty() {
		// given
		String token = "invalid-token";
		when(refreshTokenRepository.findById(token)).thenReturn(Optional.empty());

		// when
		Optional<String> resultUserId = refreshTokenService.validateAndRotate(token);

		// then
		assertThat(resultUserId).isEmpty();
		verify(refreshTokenRepository, never()).delete(any());
		verify(redisTemplate, never()).opsForSet();
	}

	@Test
	@DisplayName("사용자 ID로 토큰 폐기 시, 해당 사용자의 모든 토큰과 인덱스를 삭제해야 한다")
	void revokeRefreshTokensByUserId_ShouldDeleteAllUserTokensAndIndex() {
		// given
		String userId = "user-to-logout";
		String userTokensKey = "user_tokens:" + userId;
		Set<String> tokenIds = Set.of("token1", "token2", "token3");

		when(redisTemplate.opsForSet()).thenReturn(setOperations);
		when(setOperations.members(userTokensKey)).thenReturn(tokenIds);

		// when
		refreshTokenService.revokeRefreshTokensByUserId(userId);

		// then
		verify(setOperations).members(userTokensKey);
		verify(refreshTokenRepository).deleteAllById(tokenIds);
		verify(redisTemplate).delete(userTokensKey);
	}
}