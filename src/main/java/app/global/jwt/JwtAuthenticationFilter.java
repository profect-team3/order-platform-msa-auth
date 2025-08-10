package app.global.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final String INTERNAL_AUDIENCE = "internal-services";
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {

		String token = resolveToken(request);

		if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
			Claims claims = jwtTokenProvider.parseClaims(token);

			Set<String> audiences = claims.getAudience();
			if (audiences == null || !audiences.contains(INTERNAL_AUDIENCE)) {
				logger.warn("Invalid token audience. Expected '" + INTERNAL_AUDIENCE + "' but was '" + audiences + "'");
				filterChain.doFilter(request, response);
				return;
			}

			@SuppressWarnings("unchecked")
			List<String> roles = (List<String>) claims.get("roles", List.class);

			List<SimpleGrantedAuthority> authorities = roles.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				claims.getSubject(),
				null,
				authorities
			);

			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		filterChain.doFilter(request, response);
	}

	private String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}
		return null;
	}
}