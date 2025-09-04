package app.auth.service;

import static org.assertj.core.api.Assertions.assertThat;

import app.auth.model.entity.KeyEntry;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;


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

}
