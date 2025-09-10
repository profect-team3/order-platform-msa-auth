package app.global.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

@Configuration
public class RedisConfig {

	@Value("${REDIS_HOST}")
	private String redisHost;

	@Value("${REDIS_PORT}")
	private int redisPort;

	@Value("${REDIS_PASSWORD}")
	private String redisPassword;

	@Value("${REDIS_PROTOCOL}")
	private String redisProtocol;

	@Bean
	public LettuceConnectionFactory redisConnectionFactory() {
		RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration(redisHost, redisPort);

		LettuceClientConfiguration clientConfig;

		if (redisPassword != null && !redisPassword.isBlank()) {
			redisConfig.setPassword(redisPassword);
			clientConfig = LettuceClientConfiguration.builder().build();
		} else {
			clientConfig = LettuceClientConfiguration.builder().useSsl().build();
		}

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

	@Bean
	public ObjectMapper redisObjectMapper() {
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		return mapper;
	}
}