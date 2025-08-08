package app.global.config;

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import app.user.model.entity.enums.UserRole;
import app.global.jwt.JwtAccessDeniedHandler;
import app.global.jwt.JwtAuthenticationEntryPoint;
import app.global.jwt.JwtAuthenticationFilter;
import app.global.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

	private final JwtTokenProvider jwtTokenProvider;
	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
	private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))

			.csrf(AbstractHttpConfigurer::disable)

			.exceptionHandling(exceptions -> exceptions
				.authenticationEntryPoint(jwtAuthenticationEntryPoint)
				.accessDeniedHandler(jwtAccessDeniedHandler)
			)

			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

			.authorizeHttpRequests(auth -> auth
				.requestMatchers(
					"/v2/api-docs", "/v3/api-docs", "/v3/api-docs/**", "/swagger-resources",
					"/swagger-resources/**", "/configuration/ui", "/configuration/security", "/swagger-ui/**",
					"/webjars/**", "/swagger-ui.html",
					"/user/signup", "/user/login", "/region/**", "/payment/**"
				)
				.permitAll()

				.requestMatchers("/customer/address/**")
				.hasAnyAuthority(UserRole.CUSTOMER.name(), UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/store/**")
				.hasAnyAuthority(UserRole.OWNER.name(), UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/order/**")
				.hasAnyAuthority(UserRole.CUSTOMER.name(), UserRole.OWNER.name(), UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/customer/cart/**")
				.hasAnyAuthority(UserRole.CUSTOMER.name(), UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/customer/review/**")
				.hasAnyAuthority(UserRole.CUSTOMER.name(), UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/customer/store/**")
				.hasAnyAuthority(UserRole.CUSTOMER.name(), UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/manager/**")
				.hasAnyAuthority(UserRole.MANAGER.name(),
					UserRole.MASTER.name())

				.requestMatchers("/owner/ai/**")
				.hasAuthority(UserRole.OWNER.name())

				.anyRequest()
				.authenticated()
			)
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();

		configuration.setAllowedOrigins(Collections.singletonList("*"));
		configuration.addAllowedMethod("*");
		configuration.addAllowedHeader("*");
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}