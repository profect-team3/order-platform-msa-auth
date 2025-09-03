package app.global.jwt;

import java.io.IOException;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import app.commonUtil.apiPayload.ApiResponse;
import app.commonUtil.apiPayload.code.status.ErrorStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final ObjectMapper objectMapper;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException authException) throws IOException {

		final ErrorStatus errorStatus = ErrorStatus._UNAUTHORIZED;

		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");

		response.setStatus(errorStatus.getHttpStatus().value());

		ApiResponse<Object> errorResponse = ApiResponse.onFailure(errorStatus, null);

		objectMapper.writeValue(response.getWriter(), errorResponse);
	}
}

