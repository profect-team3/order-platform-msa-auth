package app.global.jwt;

public interface AccessTokenProvider{
	String createAccessToken(String userId, String roles);
	String createRefreshToken();
}
