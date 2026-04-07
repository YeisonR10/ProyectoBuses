package com.ysrm.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
public class GoogleOAuthService {

    @Value("${google.client-id:}")
    private String clientId;

    @Value("${google.client-secret:}")
    private String clientSecret;

    @Value("${google.redirect-uri:http://localhost:8081/security/oauth/google/callback}")
    private String redirectUri;

    public String buildAuthorizeUrl() {
        String scope = url("openid email profile");
        return "https://accounts.google.com/o/oauth2/v2/auth"
                + "?client_id=" + url(clientId)
                + "&redirect_uri=" + url(redirectUri)
                + "&response_type=code"
                + "&scope=" + scope
                + "&access_type=online"
                + "&prompt=consent";
    }

    public String exchangeCodeForAccessToken(String code) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(MediaType.parseMediaTypes("application/json"));

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://oauth2.googleapis.com/token",
                request,
                Map.class
        );
        if (response.getBody() == null) {
            return null;
        }
        Object token = response.getBody().get("access_token");
        return token == null ? null : token.toString();
    }

    public Map<String, Object> getUserInfo(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://openidconnect.googleapis.com/v1/userinfo",
                HttpMethod.GET,
                request,
                Map.class
        );
        return response.getBody();
    }

    private String url(String v) {
        return URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8);
    }
}

