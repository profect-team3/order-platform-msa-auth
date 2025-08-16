package app.auth.internal;

import app.auth.service.AuthService;

import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class InternalAuthService {
	private final AuthService authService;

	public void logout() {
		authService.logout();
	}
}
