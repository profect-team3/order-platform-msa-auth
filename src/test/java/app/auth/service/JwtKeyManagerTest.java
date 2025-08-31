package app.auth.service;

import static org.assertj.core.api.Assertions.assertThat;

import app.auth.model.entity.KeyEntry;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.services.kms.KmsClient;

class JwtKeyManagerTest {

  private JwtKeyManager jwtKeyManager;

  @BeforeEach
  void setUp() {
    // 변경된 생성자에 맞게 수정 (로컬 모드로 테스트)
    jwtKeyManager = new JwtKeyManager(false, "test-kms-key-id", Optional.empty());
    // @PostConstruct가 테스트 환경에서는 자동으로 호출되지 않으므로 수동으로 호출
    jwtKeyManager.init();
  }

  @Test
  @DisplayName("키 회전(rotateKey) 시 새로운 활성 키가 생성되고 저장되어야 한다")
  void rotateKey_ShouldGenerateAndStoreNewActiveKey() {
    // when
    KeyEntry initialKey = jwtKeyManager.getActiveKey();
    String initialKid = initialKey.kid();

    KeyEntry rotatedKey = jwtKeyManager.rotateKey();
    String rotatedKid = rotatedKey.kid();

    // then
    assertThat(rotatedKid).isNotNull();
    assertThat(rotatedKid).isNotEqualTo(initialKid);
    assertThat(jwtKeyManager.getActiveKey()).isEqualTo(rotatedKey);
    assertThat(jwtKeyManager.getKeyById(rotatedKid)).isPresent().contains(rotatedKey);
  }

  @Test
  @DisplayName("활성 키 조회(getActiveKey) 시 현재 활성화된 키를 반환해야 한다")
  void getActiveKey_ShouldReturnCurrentActiveKey() {
    // when
    KeyEntry activeKey = jwtKeyManager.getActiveKey();

    // then
    assertThat(activeKey).isNotNull();
    assertThat(activeKey.kid()).isNotNull();
    assertThat(activeKey.keyPair()).isNotNull();
  }

  @Test
  @DisplayName("ID로 키 조회(getKeyById) 시 존재하는 KID는 KeyEntry를, 없는 KID는 빈 Optional을 반환해야 한다")
  void getKeyById_ShouldReturnCorrectKeyEntry() {
    // given
    String activeKid = jwtKeyManager.getActiveKey().kid();
    String nonExistentKid = "non-existent-kid";

    // when
    Optional<KeyEntry> foundKey = jwtKeyManager.getKeyById(activeKid);
    Optional<KeyEntry> notFoundKey = jwtKeyManager.getKeyById(nonExistentKid);

    // then
    assertThat(foundKey).isPresent();
    assertThat(foundKey.get().kid()).isEqualTo(activeKid);
    assertThat(notFoundKey).isEmpty();
  }

  @Test
  @DisplayName("오래된 키 제거(removeOldKeys) 시 활성 키가 아니고 7일이 지난 키만 제거되어야 한다")
  void removeOldKeys_ShouldRemoveOnlyOldInactiveKeys() {
    // given
    // ReflectionTestUtils를 사용하여 private 필드인 keys 맵에 직접 테스트 데이터를 주입
    KeyEntry activeKey = jwtKeyManager.getActiveKey();
    KeyEntry oldInactiveKey =
        new KeyEntry(
            "old-inactive-kid", activeKey.keyPair(), Instant.now().minus(8, ChronoUnit.DAYS));
    KeyEntry recentInactiveKey =
        new KeyEntry(
            "recent-inactive-kid", activeKey.keyPair(), Instant.now().minus(1, ChronoUnit.DAYS));
    KeyEntry oldActiveKey =
        new KeyEntry(
            activeKey.kid(),
            activeKey.keyPair(),
            Instant.now().minus(10, ChronoUnit.DAYS)); // 활성키는 오래되어도 삭제되면 안됨

    Map<String, KeyEntry> testKeys = new ConcurrentHashMap<>();
    testKeys.put(oldInactiveKey.kid(), oldInactiveKey);
    testKeys.put(recentInactiveKey.kid(), recentInactiveKey);
    testKeys.put(oldActiveKey.kid(), oldActiveKey);

    // 변경된 필드 이름 'localKeys'로 수정
    ReflectionTestUtils.setField(jwtKeyManager, "localKeys", testKeys);
    ReflectionTestUtils.setField(jwtKeyManager, "activeKid", oldActiveKey.kid());

    // when
    jwtKeyManager.removeOldKeys();

    // then
    Map<String, KeyEntry> remainingKeys =
        jwtKeyManager.getAllKeys().stream()
            .collect(
                ConcurrentHashMap::new,
                (map, entry) -> map.put(entry.kid(), entry),
                ConcurrentHashMap::putAll);

    assertThat(remainingKeys).hasSize(2);
    assertThat(remainingKeys).containsKey(oldActiveKey.kid());
    assertThat(remainingKeys).containsKey(recentInactiveKey.kid());
    assertThat(remainingKeys).doesNotContainKey(oldInactiveKey.kid());
  }
}
