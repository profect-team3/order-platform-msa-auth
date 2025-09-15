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
            return "ErrorHashingValue";
        }
    }

    private static String maskForDev(String value) {
        if (value.contains("@")) {
            int atIndex = value.indexOf("@");
            if (atIndex <= 1) return "***";
            String prefix = value.substring(0, 1);
            String domain = value.substring(atIndex);
            return prefix + "***" + domain;
        }
        if (value.matches("^\\d{2,3}-\\d{3,4}-\\d{4}$")) {
            int lastHyphen = value.lastIndexOf("-");
            return value.substring(0, lastHyphen + 1) + "****";
        }
        if (value.length() <= 2) {
            return "**";
        }
        return value.substring(0, 1) + "*".repeat(value.length() - 2) + value.substring(value.length() - 1);
    }
}
