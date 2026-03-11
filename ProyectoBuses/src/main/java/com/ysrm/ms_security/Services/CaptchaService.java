package com.ysrm.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class CaptchaService {

    @Value("${captcha.enabled:false}")
    private boolean captchaEnabled;

    @Value("${captcha.secret:}")
    private String captchaSecret;

    @Value("${captcha.threshold:0.5}")
    private Double captchaThreshold;

    public boolean validateToken(String token) {
        if (!captchaEnabled) {
            return true;
        }
        if (token == null || token.isBlank()) {
            return false;
        }

        try {
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("secret", captchaSecret);
            body.add("response", token);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            Map<String, Object> response = restTemplate.postForObject(
                    "https://www.google.com/recaptcha/api/siteverify",
                    request,
                    Map.class
            );

            if (response == null || !Boolean.TRUE.equals(response.get("success"))) {
                return false;
            }

            Object score = response.get("score");
            if (score instanceof Number numberScore) {
                return numberScore.doubleValue() >= captchaThreshold;
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}

