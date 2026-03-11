package com.ysrm.ms_security.Controllers;

import com.ysrm.ms_security.Models.DTOs.ForgotPasswordRequest;
import com.ysrm.ms_security.Models.DTOs.RegisterRequest;
import com.ysrm.ms_security.Models.DTOs.ResetPasswordRequest;
import com.ysrm.ms_security.Models.DTOs.TwoFactorVerifyRequest;
import com.ysrm.ms_security.Services.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/security")
public class SecurityController {

    @Autowired
    private SecurityService theSecurityService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        Map<String, Object> response = this.theSecurityService.register(request);
        return response.containsKey("error")
                ? ResponseEntity.badRequest().body(response)
                : ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        Map<String, Object> response = this.theSecurityService.login(request);
        return response.containsKey("error")
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
                : ResponseEntity.ok(response);
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<Map<String, Object>> verify2FA(@RequestBody TwoFactorVerifyRequest request) {
        Map<String, Object> response = this.theSecurityService.verify2FA(request);
        return response.containsKey("error")
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
                : ResponseEntity.ok(response);
    }

    @PostMapping("/2fa/resend/{sessionId}")
    public ResponseEntity<Map<String, Object>> resend2FA(@PathVariable String sessionId) {
        Map<String, Object> response = this.theSecurityService.resend2FA(sessionId);
        return response.containsKey("error")
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
                : ResponseEntity.ok(response);
    }

    @DeleteMapping("/2fa/session/{sessionId}")
    public ResponseEntity<Map<String, Object>> cancelPartialSession(@PathVariable String sessionId) {
        Map<String, Object> response = this.theSecurityService.cancelPartialSession(sessionId);
        return response.containsKey("error")
                ? ResponseEntity.status(HttpStatus.NOT_FOUND).body(response)
                : ResponseEntity.ok(response);
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<Map<String, Object>> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        return ResponseEntity.ok(this.theSecurityService.forgotPassword(request));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestBody ResetPasswordRequest request) {
        Map<String, Object> response = this.theSecurityService.resetPassword(request);
        return response.containsKey("error")
                ? ResponseEntity.badRequest().body(response)
                : ResponseEntity.ok(response);
    }

    @GetMapping("/oauth/github/url")
    public Map<String, Object> githubAuthorizeUrl() {
        HashMap<String, Object> response = new HashMap<>();
        response.put("url", this.theSecurityService.getGithubAuthorizeUrl());
        return response;
    }

    @GetMapping("/oauth/github/callback")
    public ResponseEntity<Map<String, Object>> githubCallback(
            @RequestParam String code,
            @RequestParam(required = false) String alternativeEmail) {
        Map<String, Object> response = this.theSecurityService.githubCallback(code, alternativeEmail);
        return response.containsKey("error")
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
                : ResponseEntity.ok(response);
    }

    @DeleteMapping("/oauth/github/unlink/{userId}")
    public ResponseEntity<Map<String, Object>> unlinkGithub(@PathVariable String userId) {
        Map<String, Object> response = this.theSecurityService.unlinkGithub(userId);
        return response.containsKey("error")
                ? ResponseEntity.status(HttpStatus.NOT_FOUND).body(response)
                : ResponseEntity.ok(response);
    }
}
