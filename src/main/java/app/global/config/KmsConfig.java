package app.global.config;

import java.net.URI;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

@Configuration
@Profile("prod")
public class KmsConfig {

	@Value("${aws.region:}")
	private String awsRegion;

	@Value("${aws.kms.endpoint:}")
	private String kmsEndpoint;

	@Bean
	public KmsClient kmsClient() {
		KmsClientBuilder b = KmsClient.builder()
			.credentialsProvider(DefaultCredentialsProvider.create())
			.overrideConfiguration(c -> c
				.apiCallAttemptTimeout(Duration.ofSeconds(2))
				.apiCallTimeout(Duration.ofSeconds(3))
			);

		Region region = resolveRegion(awsRegion);
		b = b.region(region);

		if (kmsEndpoint != null && !kmsEndpoint.isBlank()) {
			b = b.endpointOverride(URI.create(kmsEndpoint));
		}

		return b.build();
	}

	private static Region resolveRegion(String propRegion) {
		if (propRegion != null && !propRegion.isBlank()) {
			return Region.of(propRegion);
		}

		String env = System.getenv("AWS_REGION");
		if (env != null && !env.isBlank()) return Region.of(env);

		String sys = System.getProperty("aws.region");
		if (sys != null && !sys.isBlank()) return Region.of(sys);

		return Region.AP_NORTHEAST_2;
	}
}
