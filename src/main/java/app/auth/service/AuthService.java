package app.auth.service;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import app.auth.model.repository.UserRepository;
import app.auth.model.dto.request.LoginRequest;
import app.auth.model.dto.response.LoginResponse;
import app.auth.model.entity.User;
import app.auth.status.UserErrorStatus;
import app.global.apiPayload.code.status.ErrorStatus;
import app.global.apiPayload.exception.GeneralException;
import app.global.jwt.AccessTokenProvider;
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
	private static final String REFRESH_TOKEN_PREFIX = "RT:";
	private final AccessTokenProvider accessTokenProvider;

	@Transactional
	public LoginResponse login(LoginRequest request) {
		log.debug("로그인 요청 수신 - username: {}", request.getUsername());

		User user = userRepository.findByUsername(request.getUsername())
			.orElseThrow(() -> {
				log.warn("로그인 실패 - 존재하지 않는 사용자: {}", request.getUsername());
				return new GeneralException(ErrorStatus.USER_NOT_FOUND);
			});

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			log.warn("로그인 실패 - 잘못된 비밀번호, username: {}", request.getUsername());
			throw new GeneralException(UserErrorStatus.INVALID_PASSWORD);
		}

		String roles = user.getUserRole().name();

		String accessToken = accessTokenProvider.createAccessToken(
			user.getUserId().toString(), roles
		);
		String refreshToken = accessTokenProvider.createRefreshToken();

		try {
			redisTemplate.opsForValue().set(
				REFRESH_TOKEN_PREFIX + user.getUserId(),
				refreshToken,
				jwtTokenProvider.getRefreshTokenValidityMs(),
				TimeUnit.MILLISECONDS
			);
			log.debug("Redis에 refresh token 저장 완료 - userId: {}", user.getUserId());
		} catch (Exception e) {
			log.error("Redis 저장 중 오류 발생 - userId: {}", user.getUserId(), e);
			throw e;
		}

		log.info("로그인 성공 - userId: {}, role: {}", user.getUserId(), roles);

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
		String refreshTokenKey = REFRESH_TOKEN_PREFIX + userId;

		Boolean hasKey = redisTemplate.hasKey(refreshTokenKey);
		if (hasKey != null && hasKey) {
			redisTemplate.delete(refreshTokenKey);
			log.info("로그아웃 처리 완료: 사용자 ID '{}'의 Refresh Token이 삭제되었습니다.", userId);
		} else {
			log.warn("로그아웃 시도: 사용자 ID '{}'의 Refresh Token을 찾을 수 없습니다.", userId);
		}
	}
}