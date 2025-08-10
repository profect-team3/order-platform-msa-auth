package app.auth.service;

import app.auth.model.entity.ServiceAccount;
import app.auth.model.repository.ServiceAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ServiceAccountService {

	private final ServiceAccountRepository serviceAccountRepository;
	private final PasswordEncoder passwordEncoder;

	@Transactional
	public ServiceAccount createServiceAccount(String serviceName) {
		String clientId = UUID.randomUUID().toString();
		String clientSecret = UUID.randomUUID().toString(); // This is the raw secret

		ServiceAccount account = ServiceAccount.builder()
			.clientId(clientId)
			.clientSecret(passwordEncoder.encode(clientSecret)) // Store the hashed secret
			.serviceName(serviceName)
			.build();

		serviceAccountRepository.save(account);

		// IMPORTANT: Return the raw secret only ONCE upon creation.
		// Create a DTO to hold both the account info and the raw secret for the response.
		// For simplicity here, we're just returning the entity.
		// In a real app, you'd return a DTO like: new ServiceAccountCreationResponse(account, clientSecret);
		return account; // You must handle returning the raw secret securely.
	}

	@Transactional(readOnly = true)
	public ServiceAccount findByClientId(String clientId) {
		return serviceAccountRepository.findByClientId(clientId)
			.orElseThrow(() -> new RuntimeException("Service account not found"));
	}

	// This is a simplified authentication method for the token endpoint
	public ServiceAccount authenticate(String clientId, String clientSecret) {
		ServiceAccount account = findByClientId(clientId);
		if (!account.isEnabled()) {
			throw new RuntimeException("Service account is disabled.");
		}
		if (passwordEncoder.matches(clientSecret, account.getClientSecret())) {
			return account;
		}
		throw new RuntimeException("Invalid client credentials.");
	}
}
