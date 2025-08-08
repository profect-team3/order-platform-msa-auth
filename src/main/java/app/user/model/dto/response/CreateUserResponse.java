package app.user.model.dto.response;

import app.user.model.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserResponse {
	private Long userId;

	public static CreateUserResponse from(User user) {
		return CreateUserResponse.builder()
			.userId(user.getUserId())
			.build();
	}
}
