package app.auth.service;

import app.auth.model.entity.KeyEntry;
import jakarta.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import java.security.Signature;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;


@Slf4j
@Component
public class JwtKeyManager {

  private volatile Map<String, List<Map<String, Object>>> cachedJwks;

  // KMS
  private final boolean kmsEnabled;
  private final String kmsKeyIdConfigured; // 설정값(alias or key arn)
  private final KmsClient kmsClient;
  private volatile RSAPublicKey kmsPublicKey;
  private volatile String activeKid;       // <= 공통: 현재 kid (로컬/KMS)

  // Local
  private final Map<String, KeyEntry> localKeys = new ConcurrentHashMap<>();

  @Autowired
  public JwtKeyManager(
      @Value("${kms.jwt.enabled}") boolean kmsEnabled,
      @Value("${kms.jwt.key-id:}") String kmsKeyId,
      Optional<KmsClient> kmsClient) {
    this.kmsEnabled = kmsEnabled;
    this.kmsKeyIdConfigured = kmsKeyId;
    this.kmsClient = kmsClient.orElse(null);
  }

  @PostConstruct
  public void init() {
    if (kmsEnabled) {
      log.info("Initializing JwtKeyManager in KMS mode.");
      initKms();
    } else {
      log.info("Initializing JwtKeyManager in local mode.");
      initLocal();
    }
  }

  private void initKms() {
    if (kmsClient == null) {
      throw new IllegalStateException("KMS mode is enabled, but KmsClient is not available.");
    }
    try {
      var resp = kmsClient.getPublicKey(GetPublicKeyRequest.builder()
          .keyId(kmsKeyIdConfigured).build());

      // kid는 KMS가 돌려준 실제 KeyId(ARN)를 사용 (alias 대비)
      this.activeKid = resp.keyId();

      byte[] publicKeyBytes = resp.publicKey().asByteArray();
      var keySpec = new X509EncodedKeySpec(publicKeyBytes);
      var keyFactory = KeyFactory.getInstance("RSA");
      this.kmsPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

      this.cachedJwks = null; // invalidate
      log.info("KMS public key loaded. kid={}", this.activeKid);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Failed to load public key from KMS", e);
    }
  }

  private void initLocal() {
    rotateKey();
  }

  /** 공통 API: 현재 kid 반환 */
  public String getActiveKid() {
    return this.activeKid;
  }

  /** 공통 API: 현재 공개키 반환 (KMS/Local) */
  public RSAPublicKey getActivePublicKey() {
    if (kmsEnabled) {
      if (kmsPublicKey == null) throw new IllegalStateException("KMS public key not initialized");
      return kmsPublicKey;
    }
    var key = localKeys.get(activeKid);
    if (key == null) throw new IllegalStateException("No active local key");
    return (RSAPublicKey) key.keyPair().getPublic();
  }

  /** 공통 API: RS256 서명 */
  public byte[] signRs256(byte[] message) {
    try {
      if (kmsEnabled) {
        // KMS는 digest 또는 raw message로 서명 가능. 성능 위해 digest 권장
        var digest = sha256(message);
        var signResp = kmsClient.sign(SignRequest.builder()
            .keyId(activeKid) // 실제 키 ARN
            .message(SdkBytes.fromByteArray(digest))
            .messageType(MessageType.DIGEST)
            .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
            .build());
        return signResp.signature().asByteArray();
      } else {
        var privateKey = localKeys.get(activeKid).keyPair().getPrivate();
        var sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(message);
        return sig.sign();
      }
    } catch (Exception e) {
      throw new IllegalStateException("JWT signing failed", e);
    }
  }

  private static byte[] sha256(byte[] msg) {
    try {
      var md = java.security.MessageDigest.getInstance("SHA-256");
      return md.digest(msg);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /** JWKS 제공 (공통) */
  public Map<String, List<Map<String, Object>>> getJwks() {
    var cache = this.cachedJwks;
    if (cache != null) return cache;

    List<Map<String, Object>> jwkList;
    if (kmsEnabled) {
      jwkList = List.of(convertRsaPublicKeyToJwk(getActivePublicKey(), getActiveKid()));
    } else {
      jwkList = getAllKeys().stream()
          .map(e -> convertRsaPublicKeyToJwk((RSAPublicKey) e.keyPair().getPublic(), e.kid()))
          .collect(Collectors.toList());
    }
    return this.cachedJwks = Map.of("keys", jwkList);
  }

  private Map<String, Object> convertRsaPublicKeyToJwk(RSAPublicKey rsaPublicKey, String kid) {
    byte[] nBytes = stripLeadingZero(rsaPublicKey.getModulus().toByteArray());
    byte[] eBytes = stripLeadingZero(rsaPublicKey.getPublicExponent().toByteArray());
    String n = Base64.getUrlEncoder().withoutPadding().encodeToString(nBytes);
    String e = Base64.getUrlEncoder().withoutPadding().encodeToString(eBytes);
    return Map.of(
        "kty", "RSA",
        "kid", kid,
        "use", "sig",
        "alg", "RS256",
        "n", n,
        "e", e
    );
  }

  // === Local 전용 ===

  public KeyEntry rotateKey() {
    if (kmsEnabled) {
      throw new UnsupportedOperationException("Local rotateKey is not allowed in KMS mode.");
    }
    try {
      var gen = KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      KeyPair keyPair = gen.generateKeyPair();
      String kid = UUID.randomUUID().toString();
      KeyEntry newKey = new KeyEntry(kid, keyPair, Instant.now());
      this.localKeys.put(kid, newKey);
      this.activeKid = kid;
      this.cachedJwks = null;
      return newKey;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("RSA key generation failed", e);
    }
  }

  /** (호환용) 기존 호출이 있으면 KMS 모드에서도 NPE 나지 않게 안전 반환 */
  public KeyEntry getActiveKey() {
    if (kmsEnabled) {
      // keyPair는 없지만 kid는 반환하여 호출부가 kid/JWKS용으로 쓰게 함
      return new KeyEntry(this.activeKid, null, null);
    }
    return localKeys.get(activeKid);
  }

  public Optional<KeyEntry> getKeyById(String kid) {
    if (kmsEnabled) {
      return this.activeKid != null && this.activeKid.equals(kid)
          ? Optional.of(new KeyEntry(this.activeKid, null, null))
          : Optional.empty();
    }
    return Optional.ofNullable(localKeys.get(kid));
  }

  public Collection<KeyEntry> getAllKeys() {
    if (kmsEnabled) {
      throw new UnsupportedOperationException("Key collection is not available in KMS mode.");
    }
    return localKeys.values();
  }

  // === (옵션) KMS 공개키 주기적 리프레시: alias 스위치 대응 ===
  @Scheduled(fixedDelayString = "PT5M")
  public void refreshKmsPublicKey() {
    if (!kmsEnabled) return;
    try {
      var oldKid = this.activeKid;
      initKms(); // 재조회
      if (!this.activeKid.equals(oldKid)) {
        log.info("KMS key rotated. oldKid={} newKid={}", oldKid, this.activeKid);
      }
    } catch (Exception e) {
      log.warn("KMS public key refresh failed: {}", e.toString());
    }
  }

  private static byte[] stripLeadingZero(byte[] bytes) {
    if (bytes.length > 1 && bytes[0] == 0x00) {
      byte[] copy = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, copy, 0, copy.length);
      return copy;
    }
    return bytes;
  }
}