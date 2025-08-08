package app.user.model.dto.request;

import app.user.model.entity.enums.UserRole;
import app.global.validation.annotation.ValidUserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateUserRequest {

	@NotBlank
	private String username;

	@NotBlank
	@Size(min = 8, max = 20)
	private String password;

	@NotBlank
	@Email
	private String email;

	@NotBlank
	@Size(min = 2, max = 10)
	private String nickname;

	@NotBlank
	@Size(min = 2, max = 50)
	private String realName;

	@NotBlank
	@Pattern(regexp = "^\\d{10,11}$")
	private String phoneNumber;

	@NotNull
	@ValidUserRole
	private UserRole userRole;

	public CreateUserRequest() {
	}

	public CreateUserRequest(String username, String password, String email, String nickname, String realName, String phoneNumber, UserRole userRole) {
		this.username = username;
		this.password = password;
		this.email = email;
		this.nickname = nickname;
		this.realName = realName;
		this.phoneNumber = phoneNumber;
		this.userRole = userRole;
	}
}