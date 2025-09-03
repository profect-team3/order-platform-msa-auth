package app.global.config;

import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

@Configuration
public class KmsConfig {

    @Value("${kms.jwt.region}")
    private String awsRegion;

    // This allows for overriding the KMS endpoint for local testing (e.g., with LocalStack)
    @Value("${aws.kms.endpoint:}")
    private String kmsEndpoint;

    @Bean
    public KmsClient kmsClient() {
        KmsClientBuilder builder = KmsClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(Region.of(awsRegion));

        if (kmsEndpoint != null && !kmsEndpoint.isBlank()) {
            builder.endpointOverride(URI.create(kmsEndpoint));
        }

        return builder.build();
    }
}
