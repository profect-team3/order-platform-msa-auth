package app.global.config;

import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

@Configuration
@Profile("prod")
public class KmsConfig {

	@Bean
	@Lazy
	public KmsClient kmsClient() {
		return KmsClient.builder()
			.region(Region.AP_NORTHEAST_2)
			.overrideConfiguration(c -> c
				.apiCallAttemptTimeout(Duration.ofSeconds(2))
				.apiCallTimeout(Duration.ofSeconds(3))
			)
			.build();
	}
}