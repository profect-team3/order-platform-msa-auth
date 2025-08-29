package app.global.jwt;

import java.util.List;

public interface AccessTokenProvider{
	String creatAccessToken(String userId, List<String> roles);

}
