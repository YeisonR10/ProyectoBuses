package com.ysrm.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class GithubOAuthService {

    @Value("${github.client-id:}")
    private String clientId;

    @Value("${github.client-secret:}")
    private String clientSecret;

    @Value("${github.redirect-uri:http://localhost:8081/security/oauth/github/callback}")
    private String redirectUri;

    public String buildAuthorizeUrl() {
        return "https://github.com/login/oauth/authorize?client_id=" + clientId
                + "&redirect_uri=" + redirectUri
                + "&scope=read:user%20user:email";
    }

    public String exchangeCodeForAccessToken(String code) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(MediaType.parseMediaTypes("application/json"));

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://github.com/login/oauth/access_token",
                request,
                Map.class
        );

        if (response.getBody() == null) {
            return null;
        }
        Object token = response.getBody().get("access_token");
        return token == null ? null : token.toString();
    }

    public Map<String, Object> getGithubUser(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://api.github.com/user",
                HttpMethod.GET,
                request,
                Map.class
        );

        return response.getBody();
    }

    public String getPrimaryEmail(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map[]> response = restTemplate.exchange(
                "https://api.github.com/user/emails",
                HttpMethod.GET,
                request,
                Map[].class
        );

        if (response.getBody() == null) {
            return null;
        }

        for (Map emailObj : response.getBody()) {
            Object primary = emailObj.get("primary");
            Object verified = emailObj.get("verified");
            if (Boolean.TRUE.equals(primary) && Boolean.TRUE.equals(verified)) {
                Object email = emailObj.get("email");
                return email == null ? null : email.toString();
            }
        }
        return null;
    }
}

