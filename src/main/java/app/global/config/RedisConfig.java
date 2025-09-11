package app.global.config;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.fasterxml.jackson.databind.SerializationFeature;

@Configuration
public class RedisConfig {

	@Value("${REDIS_HOST}")
	private String redisHost;

	@Value("${REDIS_PORT}")
	private int redisPort;

	@Value("${REDIS_PASSWORD:}") // 빈 문자열 기본값
	private String redisPassword;

	@Value("${REDIS_PROTOCOL:redis}")
	private String redisProtocol;

	@Bean
	public LettuceConnectionFactory redisConnectionFactory() {
		RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration();
		redisConfig.setHostName(redisHost);
		redisConfig.setPort(redisPort);

		if (redisPassword != null && !redisPassword.isBlank()) {
			redisConfig.setPassword(redisPassword);
		}

		LettuceClientConfiguration.LettuceClientConfigurationBuilder clientConfigBuilder =
			LettuceClientConfiguration.builder()
				.commandTimeout(Duration.ofSeconds(60))
				.shutdownTimeout(Duration.ofMillis(100));

		if ("rediss".equalsIgnoreCase(redisProtocol)) {
			clientConfigBuilder.useSsl();
		}

		// if ("rediss".equalsIgnoreCase(redisProtocol) || redisPort == 6380) {
		// 	clientConfigBuilder.useSsl();
		// }

		LettuceClientConfiguration clientConfig = clientConfigBuilder.build();
		return new LettuceConnectionFactory(redisConfig, clientConfig);
	}

	@Bean
	public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
		RedisTemplate<String, String> template = new RedisTemplate<>();
		template.setConnectionFactory(connectionFactory);
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(new StringRedisSerializer());
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(new StringRedisSerializer());
		return template;
	}
}
