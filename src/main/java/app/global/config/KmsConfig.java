package app.global.config;

import java.net.URI;
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

    @Value("${kms.jwt.region}")
    private String awsRegion;

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
