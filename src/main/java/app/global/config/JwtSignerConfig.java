package app.global.config;

import app.global.jwt.KmsRsaSigner;
import com.nimbusds.jose.JWSSigner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

@Configuration
@Profile("prod")
public class JwtSignerConfig {

	@Value("${kms.jwt.key-id}")
	private String kmsKeyId;

	@Value("${kms.jwt.signing-alg:RSASSA_PKCS1_V1_5_SHA_256}")
	private String signingAlg;

	@Bean(name = "kmsRsaSigner")
	public KmsRsaSigner jwsSigner(KmsClient kmsClient) {
		SigningAlgorithmSpec alg = SigningAlgorithmSpec.fromValue(signingAlg);
		return new KmsRsaSigner(kmsClient, kmsKeyId, alg);
	}
}
