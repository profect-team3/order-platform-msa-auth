package app.global.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.util.Base64URL;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
import java.security.MessageDigest;
import java.util.Collections;

@Slf4j
public class KmsRsaSigner extends BaseJWSProvider implements JWSSigner {

	private final KmsClient kms;
	private final String keyId;
	private final SigningAlgorithmSpec kmsAlg;

	public KmsRsaSigner(KmsClient kms, String keyId, SigningAlgorithmSpec kmsAlg) {
		super(kmsAlg == SigningAlgorithmSpec.RSASSA_PSS_SHA_256
			? Collections.singleton(JWSAlgorithm.PS256)
			: Collections.singleton(JWSAlgorithm.RS256));
		this.kms = kms;
		this.keyId = keyId;
		this.kmsAlg = kmsAlg;
	}

	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(signingInput);

			SignResponse res = kms.sign(SignRequest.builder()
				.keyId(keyId)
				.signingAlgorithm(kmsAlg)
				.messageType(MessageType.DIGEST)
				.message(SdkBytes.fromByteArray(digest))
				.build());


			return Base64URL.encode(res.signature().asByteArray());
		} catch (KmsException e) {
			String code = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "KmsException";
			String msg  = e.awsErrorDetails() != null ? e.awsErrorDetails().errorMessage() : e.getMessage();
			throw new JOSEException("KMS sign failed: " + code + " - " + msg, e);
		} catch (Exception e) {
			log.error("JWT sign failed", e); // ★ root cause 로그
			throw new IllegalStateException("JWT sign failed: " + e.getMessage(), e);
		}
	}
}