package app.user.model;

import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import app.user.model.entity.User;
import app.user.model.entity.enums.UserRole;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String userName);

	Optional<User> findByUserId(Long userId);

	Page<User> findAllByUserRole(UserRole role, Pageable pageable);
}