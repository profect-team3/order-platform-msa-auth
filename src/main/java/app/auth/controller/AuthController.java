package app.auth.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import app.auth.model.dto.request.LoginRequest;
import app.auth.model.dto.response.LoginResponse;
import app.auth.service.AuthService;
import app.auth.status.UserSuccessStatus;
import app.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Tag(name = "Auth", description = "로그인, 로그아웃")
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

	private final AuthService authService;

	@PostMapping("/login")
	@Operation(summary = "로그인 API", description = "아이디와 비밀번호로 로그인하여 토큰을 발급받습니다.")
	public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
		LoginResponse response = authService.login(request);
		return ApiResponse.onSuccess(UserSuccessStatus.LOGIN_SUCCESS, response);
	}

	@PostMapping("/logout")
	@Operation(summary = "로그아웃 API", description = "서버에 저장된 Refresh Token을 삭제합니다.")
	public ApiResponse<Void> logout() {
		authService.logout();
		return ApiResponse.onSuccess(UserSuccessStatus.LOGOUT_SUCCESS, null);
	}
}