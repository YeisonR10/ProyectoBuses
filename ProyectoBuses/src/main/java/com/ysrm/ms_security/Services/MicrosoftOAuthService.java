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
public class MicrosoftOAuthService {

    @Value("${microsoft.client-id:}")
    private String clientId;

    @Value("${microsoft.client-secret:}")
    private String clientSecret;

    @Value("${microsoft.redirect-uri:http://localhost:8081/security/oauth/microsoft/callback}")
    private String redirectUri;

    @Value("${microsoft.tenant:common}")
    private String tenant;

    public String buildAuthorizeUrl() {
        // "common" soporta cuentas personales y organizacionales.
        String scope = url("openid profile email User.Read");
        return "https://login.microsoftonline.com/" + url(tenant) + "/oauth2/v2.0/authorize"
                + "?client_id=" + url(clientId)
                + "&redirect_uri=" + url(redirectUri)
                + "&response_type=code"
                + "&response_mode=query"
                + "&scope=" + scope;
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
        body.add("scope", "openid profile email User.Read");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
                request,
                Map.class
        );

        if (response.getBody() == null) {
            return null;
        }
        Object token = response.getBody().get("access_token");
        return token == null ? null : token.toString();
    }

    public Map<String, Object> getMicrosoftProfile(String accessToken) {
        // Graph: devuelve displayName y correo (mail o userPrincipalName)
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://graph.microsoft.com/v1.0/me",
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

