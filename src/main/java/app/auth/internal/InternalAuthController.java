package app.auth.internal;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import app.auth.status.UserSuccessStatus;
import app.global.apiPayload.ApiResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("internal/auth")
public class InternalAuthController {
	private final InternalAuthService internalAuthService;

	@PostMapping("/logout")
	public ApiResponse<Void> logout() {
		internalAuthService.logout();
		return ApiResponse.onSuccess(UserSuccessStatus.LOGOUT_SUCCESS, null);
	}
}
