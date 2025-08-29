package app.global.jwt;

import java.util.List;

public interface AccessTokenProvider{
	String createAccessToken(String userId, List<String> roles);

}
