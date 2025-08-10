package app.auth.model.repository;

import app.auth.model.entity.ServiceAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ServiceAccountRepository extends JpaRepository<ServiceAccount, Long> {
	Optional<ServiceAccount> findByClientId(String clientId);
}
