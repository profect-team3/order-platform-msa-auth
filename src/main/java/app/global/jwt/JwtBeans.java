package app.global.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import java.net.URI;

@Configuration
@Profile("prod")
public class JwtBeans {

	@Value("${aws.region:}")
	private String awsRegion;

	@Value("${aws.kms.endpoint:}")
	private String kmsEndpoint;


	@Bean
	public KmsClient kmsClient() {
		KmsClientBuilder b = KmsClient.builder()
			.credentialsProvider(DefaultCredentialsProvider.create());

		Region region = resolveRegion(awsRegion);
		b = b.region(region);

		if (!kmsEndpoint.isBlank()) {
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