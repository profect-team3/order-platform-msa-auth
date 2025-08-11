package app.auth.service;

import app.auth.model.entity.RefreshToken;
import app.auth.model.repository.RefreshTokenRepository;
import app.global.jwt.JwtTokenProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;
	private final JwtTokenProvider jwtTokenProvider;
	private final RedisTemplate<String, String> redisTemplate;
	private static final String USER_TOKENS_PREFIX = "user_tokens:";


	@Transactional
	public String createRefreshToken(String userId) {
		String token = UUID.randomUUID().toString();
		long refreshTokenValidityMs = jwtTokenProvider.getRefreshTokenValidityMs();
		long ttlInSeconds = TimeUnit.MILLISECONDS.toSeconds(refreshTokenValidityMs);

		RefreshToken refreshToken = new RefreshToken(token, userId, ttlInSeconds);
		refreshTokenRepository.save(refreshToken);

		String userTokensKey = USER_TOKENS_PREFIX + userId;
		redisTemplate.opsForSet().add(userTokensKey, token);
		redisTemplate.expire(userTokensKey, ttlInSeconds, TimeUnit.SECONDS);

		return token;
	}

	@Transactional
	public Optional<String> validateAndRotate(String token) {
		return refreshTokenRepository.findById(token)
			.map(foundToken -> {
				String userId = foundToken.getUserId();

				refreshTokenRepository.delete(foundToken);

				redisTemplate.opsForSet().remove(USER_TOKENS_PREFIX + userId, token);

				return userId;
			});
	}

	@Transactional
	public void revokeRefreshTokensByUserId(String userId) {
		String userTokensKey = USER_TOKENS_PREFIX + userId;

		Set<String> tokenIds = redisTemplate.opsForSet().members(userTokensKey);

		if (tokenIds != null && !tokenIds.isEmpty()) {
			refreshTokenRepository.deleteAllById(tokenIds);
		}

		redisTemplate.delete(userTokensKey);
	}
}