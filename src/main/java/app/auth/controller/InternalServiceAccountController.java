package app.auth.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import app.auth.model.entity.ServiceAccount;
import app.auth.service.ServiceAccountService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/master/service-accounts")
@RequiredArgsConstructor
public class InternalServiceAccountController {

	private final ServiceAccountService serviceAccountService;

	@PostMapping
	public ResponseEntity<?> createServiceAccount(@RequestBody Map<String, String> request) {
		String serviceName = request.get("serviceName");
		ServiceAccount account = serviceAccountService.createServiceAccount(serviceName);
		return ResponseEntity.status(HttpStatus.CREATED).body(account);
	}
}
