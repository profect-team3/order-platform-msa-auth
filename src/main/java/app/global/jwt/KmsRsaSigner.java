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
	private final SigningAlgorithmSpec kmsAlg; // RSASSA_PKCS1_V1_5_SHA_256 or RSASSA_PSS_SHA_256

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
			// 1) JWS 규격에 따라 SHA-256 해시를 우리가 계산
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(signingInput);

			// 2) KMS에 DIGEST 타입으로 서명 요청
			SignResponse res = kms.sign(SignRequest.builder()
				.keyId(keyId)
				.signingAlgorithm(kmsAlg)
				.messageType(MessageType.DIGEST)
				.message(SdkBytes.fromByteArray(digest))
				.build());

			// 3) KMS가 주는 시그니처(RSA raw)는 그대로 반환 (Nimbus가 Base64URL 인코딩함)
			return Base64URL.encode(res.signature().asByteArray());
		} catch (KmsException e) {
			// 원인 파악 도움되도록 상세 메시지 올리기
			String code = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "KmsException";
			String msg  = e.awsErrorDetails() != null ? e.awsErrorDetails().errorMessage() : e.getMessage();
			throw new JOSEException("KMS sign failed: " + code + " - " + msg, e);
		} catch (Exception e) {
			log.error("JWT sign failed", e); // ★ root cause 로그
			throw new IllegalStateException("JWT sign failed: " + e.getMessage(), e);
		}
	}
}