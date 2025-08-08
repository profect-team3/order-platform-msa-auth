package app.user.model.dto.response;

import app.user.model.entity.User;
import app.user.model.entity.enums.UserRole;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class GetUserInfoResponse {

	private Long userId;
	private String username;
	private String email;
	private String nickname;
	private String realName;
	private String phoneNumber;
	private UserRole userRole;

	public GetUserInfoResponse() {
	}

	public GetUserInfoResponse(Long userId, String username, String email, String nickname, String realName, String phoneNumber, UserRole userRole) {
		this.userId = userId;
		this.username = username;
		this.email = email;
		this.nickname = nickname;
		this.realName = realName;
		this.phoneNumber = phoneNumber;
		this.userRole = userRole;
	}

	public static GetUserInfoResponse from(User user) {
		return GetUserInfoResponse.builder()
			.userId(user.getUserId())
			.username(user.getUsername())
			.email(user.getEmail())
			.nickname(user.getNickname())
			.realName(user.getRealName())
			.phoneNumber(user.getPhoneNumber())
			.userRole(user.getUserRole())
			.build();
	}
}
