package app.auth.controller;

import app.auth.service.JwtKeyManager;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
@Profile("prod")
public class JwksController {

  private final JwtKeyManager jwtKeyManager;

  @GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<Map<String, List<Map<String, Object>>>> jwks() {
    return ResponseEntity.ok(jwtKeyManager.getJwks());
  }
}