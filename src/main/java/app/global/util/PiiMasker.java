package app.global.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Component
public class PiiMasker {

    private static String activeProfile;
    private static String logSalt;

    @Value("${spring.profiles.active:dev}")
    private String profile;

    @Value("${log.salt:default_salt_for_dev}")
    private String salt;

    @PostConstruct
    public void init() {
        activeProfile = profile;
        logSalt = salt;
    }

    /**
     * active profile에 따라 개인정보를 마스킹하거나 해싱합니다.
     * @param value 마스킹할 원본 문자열
     * @return 처리된 문자열
     */
    public static String mask(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        if ("prod".equals(activeProfile)) {
            return hashWithSalt(value);
        } else {
            return maskForDev(value);
        }
    }

    /**
     * SHA-256과 Salt를 사용하여 값을 해싱합니다. (운영용)
     */
    private static String hashWithSalt(String value) {
        if (logSalt == null || logSalt.isEmpty() || "default_salt_for_dev".equals(logSalt)) {
            return "SALT_NOT_CONFIGURED";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(logSalt.getBytes(StandardCharsets.UTF_8));
            byte[] hashedBytes = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            // 실제 운영 환경에서는 로깅 및 예외 처리를 더 견고하게 해야 합니다.
            return "ErrorHashingValue";
        }
    }

    /**
     * 개발/테스트 환경을 위해 값을 마스킹합니다.
     */
    private static String maskForDev(String value) {
        // 이메일 형식 마스킹
        if (value.contains("@")) {
            int atIndex = value.indexOf("@");
            if (atIndex <= 1) return "***";
            String prefix = value.substring(0, 1);
            String domain = value.substring(atIndex);
            return prefix + "***" + domain;
        }
        // 전화번호 형식 마스킹 (e.g., 010-1234-5678)
        if (value.matches("^\\d{2,3}-\\d{3,4}-\\d{4}$")) {
            int lastHyphen = value.lastIndexOf("-");
            return value.substring(0, lastHyphen + 1) + "****";
        }
        // 일반 문자열 마스킹
        if (value.length() <= 2) {
            return "**";
        }
        return value.substring(0, 1) + "*".repeat(value.length() - 2) + value.substring(value.length() - 1);
    }
}
