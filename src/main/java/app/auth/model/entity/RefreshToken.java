package app.auth.model.entity;

import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@RedisHash(value = "p_refresh_token")
public class RefreshToken {

	@Id
	private String token;

	private String userId;

	@TimeToLive
	private Long ttl;
}