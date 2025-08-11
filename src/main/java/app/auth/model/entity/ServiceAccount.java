package app.auth.model.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "service_account", indexes = @Index(name = "idx_client_id", columnList = "clientId", unique = true))
public class ServiceAccount {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true)
	private String clientId;

	@Column(nullable = false)
	private String clientSecret; // Hashed secret

	@Column(nullable = false)
	private String serviceName;

	@Column(nullable = false)
	private boolean enabled = true;

	@Column(updatable = false)
	private Instant createdAt;

	@Builder
	public ServiceAccount(String clientId, String clientSecret, String serviceName) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.serviceName = serviceName;
		this.createdAt = Instant.now();
	}

	public void setClientSecret(String newHashedSecret) {
		this.clientSecret = newHashedSecret;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
}