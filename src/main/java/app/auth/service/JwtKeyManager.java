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

@Slf4j
@Component
public class JwtKeyManager {

  // --- Common Fields ---
  private volatile Map<String, List<Map<String, Object>>> cachedJwks;

  // --- KMS Mode Fields ---
  private final boolean kmsEnabled;
  private final String kmsKeyId;
  private final KmsClient kmsClient;
  private PublicKey kmsPublicKey;

  // --- Local Mode Fields ---
  private final Map<String, KeyEntry> localKeys = new ConcurrentHashMap<>();
  private volatile String activeKid;

  @Autowired
  public JwtKeyManager(
      @Value("${kms.jwt.enabled}") boolean kmsEnabled,
      @Value("${kms.jwt.key-id}") String kmsKeyId,
      Optional<KmsClient> kmsClient) {
    this.kmsEnabled = kmsEnabled;
    this.kmsKeyId = kmsKeyId;
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
      GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(kmsKeyId).build();
      GetPublicKeyResponse response = kmsClient.getPublicKey(request);
      byte[] publicKeyBytes = response.publicKey().asByteArray();
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      this.kmsPublicKey = keyFactory.generatePublic(keySpec);
      this.cachedJwks = null; // Invalidate cache on init
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Failed to load public key from KMS", e);
    }
  }

  private void initLocal() {
    rotateKey();
  }

  public Map<String, List<Map<String, Object>>> getJwks() {
    if (this.cachedJwks != null) {
      return this.cachedJwks;
    }

    if (kmsEnabled) {
      this.cachedJwks = buildJwksFromKms();
    } else {
      this.cachedJwks = buildJwksFromLocal();
    }
    return this.cachedJwks;
  }

  private Map<String, List<Map<String, Object>>> buildJwksFromKms() {
    if (this.kmsPublicKey == null) {
      throw new IllegalStateException("KMS public key is not initialized.");
    }
    RSAPublicKey rsaPublicKey = (RSAPublicKey) this.kmsPublicKey;
    List<Map<String, Object>> jwkList =
        List.of(convertRsaPublicKeyToJwk(rsaPublicKey, this.kmsKeyId));
    return Map.of("keys", jwkList);
  }

  private Map<String, List<Map<String, Object>>> buildJwksFromLocal() {
    List<Map<String, Object>> jwkList =
        this.getAllKeys().stream()
            .map(
                entry -> {
                  RSAPublicKey pub = (RSAPublicKey) entry.keyPair().getPublic();
                  return convertRsaPublicKeyToJwk(pub, entry.kid());
                })
            .collect(Collectors.toList());
    return Map.of("keys", jwkList);
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
        "e", e);
  }

  private static byte[] stripLeadingZero(byte[] bytes) {
    if (bytes.length > 1 && bytes[0] == 0x00) {
      byte[] copy = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, copy, 0, copy.length);
      return copy;
    }
    return bytes;
  }

  // --- Local Mode Methods ---

  public KeyEntry rotateKey() {
    if (kmsEnabled) {
      throw new UnsupportedOperationException("Key rotation is not supported in KMS mode.");
    }
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      String kid = UUID.randomUUID().toString();
      KeyEntry newKey = new KeyEntry(kid, keyPair, Instant.now());

      this.localKeys.put(kid, newKey);
      this.activeKid = kid;
      this.cachedJwks = null; // Invalidate cache

      return newKey;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("RSA key generation failed", e);
    }
  }

  public KeyEntry getActiveKey() {
    if (kmsEnabled) {
      throw new UnsupportedOperationException("Active key is not available in KMS mode.");
    }
    return localKeys.get(activeKid);
  }

  public Optional<KeyEntry> getKeyById(String kid) {
    if (kmsEnabled) {
      // In KMS mode, we only have one key. Check if the provided kid matches.
      return this.kmsKeyId.equals(kid)
          ? Optional.of(new KeyEntry(this.kmsKeyId, null, null)) // KeyPair and Instant are not available
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

  @Scheduled(cron = "0 0 0 * * ?")
  public void removeOldKeys() {
    if (kmsEnabled) {
      return; // Do nothing in KMS mode
    }
    Instant cutoff = Instant.now().minus(Duration.ofDays(7));
    boolean removed =
        localKeys.entrySet().removeIf(
            entry ->
                !entry.getKey().equals(activeKid) && entry.getValue().createdAt().isBefore(cutoff));

    if (removed) {
      this.cachedJwks = null; // Invalidate cache
    }
  }
}
