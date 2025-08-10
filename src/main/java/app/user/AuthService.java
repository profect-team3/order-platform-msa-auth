package app.user;

import java.util.concurrent.TimeUnit;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import app.user.model.UserRepository;
import app.user.model.dto.request.CreateUserRequest;
import app.user.model.dto.request.LoginRequest;
import app.user.model.dto.response.CreateUserResponse;
import app.user.model.dto.response.GetUserInfoResponse;
import app.user.model.dto.response.LoginResponse;
import app.user.model.entity.User;
import app.user.status.UserErrorStatus;
import app.global.SecurityUtil;
import app.global.apiPayload.code.status.ErrorStatus;
import app.global.apiPayload.exception.GeneralException;
import app.global.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtTokenProvider jwtTokenProvider;
	private final RedisTemplate<String, String> redisTemplate;
	private final SecurityUtil securityUtil;
	private static final String REFRESH_TOKEN_PREFIX = "RT:";
	private static final String BLACKLIST_PREFIX = "BL:";

	@Transactional
	public LoginResponse login(LoginRequest request) {
		User user = userRepository.findByUsername(request.getUsername())
			.orElseThrow(() -> new GeneralException(ErrorStatus.USER_NOT_FOUND));

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new GeneralException(UserErrorStatus.INVALID_PASSWORD);
		}

		String accessToken = jwtTokenProvider.createAccessToken(user);
		String refreshToken = jwtTokenProvider.createRefreshToken(user);

		redisTemplate.opsForValue().set(
			REFRESH_TOKEN_PREFIX + user.getUserId(),
			refreshToken,
			jwtTokenProvider.getRefreshTokenValidityInMilliseconds(),
			TimeUnit.MILLISECONDS
		);

		return LoginResponse.builder()
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.build();
	}

	@Transactional
	public void logout() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(
			authentication.getPrincipal())) {
			throw new GeneralException(UserErrorStatus.AUTHENTICATION_NOT_FOUND);
		}

		String userId = authentication.getName();
		Object credentials = authentication.getCredentials();
		if (!(credentials instanceof String accessToken)) {
			String refreshTokenKey = REFRESH_TOKEN_PREFIX + userId;
			if (Boolean.TRUE.equals(redisTemplate.hasKey(refreshTokenKey))) {
				redisTemplate.delete(refreshTokenKey);
			}
			return;
		}

		String refreshTokenKey = REFRESH_TOKEN_PREFIX + userId;
		if (Boolean.TRUE.equals(redisTemplate.hasKey(refreshTokenKey))) {
			redisTemplate.delete(refreshTokenKey);
		}

		Long expiration = jwtTokenProvider.getExpiration(accessToken);
		if (expiration > 0) {
			redisTemplate.opsForValue().set(
				BLACKLIST_PREFIX + accessToken,
				"logout",
				expiration,
				TimeUnit.MILLISECONDS
			);
		}
	}
}