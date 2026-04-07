package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.DTOs.ForgotPasswordRequest;
import com.ysrm.ms_security.Models.DTOs.RegisterRequest;
import com.ysrm.ms_security.Models.DTOs.ResetPasswordRequest;
import com.ysrm.ms_security.Models.DTOs.TwoFactorVerifyRequest;
import com.ysrm.ms_security.Models.PasswordResetToken;
import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.Session;
import com.ysrm.ms_security.Models.User;
import com.ysrm.ms_security.Models.UserRole;
import com.ysrm.ms_security.Repositories.PasswordResetTokenRepository;
import com.ysrm.ms_security.Repositories.RoleRepository;
import com.ysrm.ms_security.Repositories.SessionRepository;
import com.ysrm.ms_security.Repositories.UserRepository;
import com.ysrm.ms_security.Repositories.UserRoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.*;

@Service
public class SecurityService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityService.class);

    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private UserRoleRepository theUserRoleRepository;
    @Autowired
    private RoleRepository theRoleRepository;
    @Autowired
    private SessionRepository theSessionRepository;
    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired
    private PasswordHashService passwordHashService;
    @Autowired
    private JwtService theJwtService;
    @Autowired
    private PasswordPolicyService passwordPolicyService;
    @Autowired
    private CaptchaService captchaService;
    @Autowired
    private GithubOAuthService githubOAuthService;
    @Autowired
    private GoogleOAuthService googleOAuthService;
    @Autowired
    private MicrosoftOAuthService microsoftOAuthService;
    @Autowired
    private EmailService emailService;

    @Value("${security.otp.expiration-ms:300000}")
    private Long otpExpirationMs;

    @Value("${security.reset.expiration-ms:1800000}")
    private Long resetExpirationMs;

    @Value("${security.reset.base-url:https://sistema.com/reset-password?token=}")
    private String resetBaseUrl;

    @Value("${jwt.expiration:3600000}")
    private Long jwtExpirationMs;

    public Map<String, Object> register(RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            return error("El email es obligatorio");
        }
        if (theUserRepository.existsByEmail(request.getEmail())) {
            return error("El email ya esta registrado");
        }
        if (!Objects.equals(request.getPassword(), request.getConfirmPassword())) {
            return error("Las contrasenas no coinciden");
        }
        if (!passwordPolicyService.isValid(request.getPassword())) {
            return error("La contrasena no cumple la politica de seguridad");
        }

        User user = new User();
        user.setName(request.getName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordHashService.hashNew(request.getPassword()));
        theUserRepository.save(user);
        ensureDefaultCitizenRole(user);

        emailService.sendAccountCreated(user.getEmail(), user.getName() + " " + Optional.ofNullable(user.getLastName()).orElse(""));
        response.put("message", "Usuario registrado correctamente");
        return response;
    }

    public Map<String, Object> login(Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");
        String recaptchaToken = request.get("recaptchaToken");

        if (!captchaService.validateToken(recaptchaToken)) {
            return error("Captcha invalido");
        }

        User actualUser = this.theUserRepository.getUserByEmail(email);
        if (actualUser == null || !passwordHashService.verifyAndUpgradeIfNeeded(actualUser, password)) {
            return error("Email o contrasena incorrectos");
        }
        // Migra hash legacy si aplica.
        theUserRepository.save(actualUser);

        String code = generateNumericCode(6);
        Session partialSession = new Session();
        partialSession.setUser(actualUser);
        partialSession.setCode2FA(code);
        partialSession.setOtpAttempts(0);
        partialSession.setOtpVerified(false);
        partialSession.setPartialAuth(true);
        partialSession.setCreatedAt(new Date());
        partialSession.setExpiration(new Date(System.currentTimeMillis() + otpExpirationMs));
        theSessionRepository.save(partialSession);

        emailService.sendTwoFactorCode(actualUser.getEmail(), code);

        Map<String, Object> response = new HashMap<>();
        response.put("requires2FA", true);
        response.put("sessionId", partialSession.getId());
        response.put("maskedEmail", maskEmail(actualUser.getEmail()));
        response.put("expiresInSeconds", otpExpirationMs / 1000);
        response.put("message", "Codigo enviado al correo registrado");
        return response;
    }

    public Map<String, Object> verify2FA(TwoFactorVerifyRequest request) {
        if (request.getCode() == null || !request.getCode().matches("\\d{6}")) {
            return error("El codigo debe contener 6 digitos");
        }

        Session session = theSessionRepository.findById(request.getSessionId()).orElse(null);
        if (session == null || !Boolean.TRUE.equals(session.getPartialAuth())) {
            return error("Sesion parcial invalida");
        }
        if (session.getExpiration() != null && session.getExpiration().before(new Date())) {
            theSessionRepository.delete(session);
            return error("Codigo expirado");
        }

        int attempts = Optional.ofNullable(session.getOtpAttempts()).orElse(0);
        if (!Objects.equals(session.getCode2FA(), request.getCode())) {
            attempts += 1;
            session.setOtpAttempts(attempts);
            if (attempts >= 3) {
                theSessionRepository.delete(session);
                return error("Codigo incorrecto. Intentos restantes: 0");
            }
            theSessionRepository.save(session);
            return error("Codigo incorrecto. Intentos restantes: " + (3 - attempts));
        }

        List<String> roles = getRolesByUser(session.getUser());
        String token = theJwtService.generateToken(session.getUser(), roles);

        session.setToken(token);
        session.setPartialAuth(false);
        session.setOtpVerified(true);
        session.setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs));
        theSessionRepository.save(session);

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("message", "Autenticacion completada");
        return response;
    }

    public Map<String, Object> resend2FA(String sessionId) {
        Session session = theSessionRepository.findById(sessionId).orElse(null);
        if (session == null || !Boolean.TRUE.equals(session.getPartialAuth()) || session.getUser() == null) {
            return error("Sesion parcial invalida");
        }

        String code = generateNumericCode(6);
        session.setCode2FA(code);
        session.setOtpAttempts(0);
        session.setCreatedAt(new Date());
        session.setExpiration(new Date(System.currentTimeMillis() + otpExpirationMs));
        theSessionRepository.save(session);

        emailService.sendTwoFactorCode(session.getUser().getEmail(), code);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Codigo reenviado correctamente");
        response.put("maskedEmail", maskEmail(session.getUser().getEmail()));
        response.put("expiresInSeconds", otpExpirationMs / 1000);
        return response;
    }

    public Map<String, Object> cancelPartialSession(String sessionId) {
        Session session = theSessionRepository.findById(sessionId).orElse(null);
        if (session == null) {
            return error("Sesion parcial invalida");
        }
        theSessionRepository.delete(session);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Sesion parcial invalidada");
        return response;
    }

    public Map<String, Object> forgotPassword(ForgotPasswordRequest request) {
        if (!captchaService.validateToken(request.getRecaptchaToken())) {
            return error("Captcha invalido");
        }

        User user = theUserRepository.getUserByEmail(request.getEmail());
        if (user != null) {
            PasswordResetToken reset = new PasswordResetToken();
            reset.setUser(user);
            reset.setToken(UUID.randomUUID().toString());
            reset.setUsed(false);
            reset.setExpiration(new Date(System.currentTimeMillis() + resetExpirationMs));
            passwordResetTokenRepository.save(reset);
            emailService.sendPasswordReset(user.getEmail(), resetBaseUrl + reset.getToken());
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Si el email existe, recibira instrucciones de recuperacion");
        return response;
    }

    public Map<String, Object> resetPassword(ResetPasswordRequest request) {
        if (!Objects.equals(request.getPassword(), request.getConfirmPassword())) {
            return error("Las contrasenas no coinciden");
        }
        if (!passwordPolicyService.isValid(request.getPassword())) {
            return error("La contrasena no cumple la politica de seguridad");
        }

        PasswordResetToken reset = passwordResetTokenRepository.getByToken(request.getToken());
        if (reset == null || reset.isUsed() || reset.getExpiration().before(new Date())) {
            return error("Token de recuperacion invalido o expirado");
        }

        User user = reset.getUser();
        user.setPassword(passwordHashService.hashNew(request.getPassword()));
        theUserRepository.save(user);

        reset.setUsed(true);
        passwordResetTokenRepository.save(reset);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Contrasena actualizada correctamente");
        return response;
    }

    public String getGithubAuthorizeUrl() {
        return githubOAuthService.buildAuthorizeUrl();
    }

    public String getGoogleAuthorizeUrl() {
        return googleOAuthService.buildAuthorizeUrl();
    }

    public String getMicrosoftAuthorizeUrl() {
        return microsoftOAuthService.buildAuthorizeUrl();
    }

    public Map<String, Object> githubCallback(String code, String alternativeEmail) {
        String accessToken = githubOAuthService.exchangeCodeForAccessToken(code);
        if (accessToken == null) {
            return error("No fue posible autenticar con GitHub");
        }

        Map<String, Object> ghUser = githubOAuthService.getGithubUser(accessToken);
        if (ghUser == null) {
            return error("No fue posible obtener perfil de GitHub");
        }

        String githubId = String.valueOf(ghUser.get("id"));
        String githubUsername = ghUser.get("login") == null ? null : ghUser.get("login").toString();
        String githubName = ghUser.get("name") == null ? githubUsername : ghUser.get("name").toString();
        String avatar = ghUser.get("avatar_url") == null ? null : ghUser.get("avatar_url").toString();

        String email = githubOAuthService.getPrimaryEmail(accessToken);
        if ((email == null || email.isBlank()) && (alternativeEmail == null || alternativeEmail.isBlank())) {
            return error("GitHub no compartio email. Debe enviar email alternativo");
        }
        if (email == null || email.isBlank()) {
            email = alternativeEmail;
        }

        User user = theUserRepository.getUserByGithubId(githubId);
        if (user == null) {
            user = theUserRepository.getUserByEmail(email);
        }
        if (user == null) {
            user = new User();
            user.setEmail(email);
            user.setName(githubName);
            user.setPassword(passwordHashService.hashNew(UUID.randomUUID().toString()));
        }

        user.setGithubId(githubId);
        user.setGithubUsername(githubUsername);
        user.setGithubAvatarUrl(avatar);
        theUserRepository.save(user);
        ensureDefaultCitizenRole(user);

        String token = theJwtService.generateToken(user, getRolesByUser(user));
        createSessionForToken(user, token);
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("githubUsername", githubUsername);
        return response;
    }

    public Map<String, Object> unlinkGithub(String userId) {
        User user = theUserRepository.findById(userId).orElse(null);
        if (user == null) {
            return error("Usuario no encontrado");
        }

        user.setGithubId(null);
        user.setGithubUsername(null);
        user.setGithubAvatarUrl(null);
        theUserRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Cuenta GitHub desvinculada");
        return response;
    }

    public Map<String, Object> googleCallback(String code) {
        String accessToken = googleOAuthService.exchangeCodeForAccessToken(code);
        if (accessToken == null) {
            return error("No fue posible autenticar con Google");
        }

        Map<String, Object> info = googleOAuthService.getUserInfo(accessToken);
        if (info == null) {
            return error("No fue posible obtener perfil de Google");
        }

        String googleId = info.get("sub") == null ? null : info.get("sub").toString();
        String email = info.get("email") == null ? null : info.get("email").toString();
        String name = info.get("name") == null ? null : info.get("name").toString();
        String picture = info.get("picture") == null ? null : info.get("picture").toString();

        if (email == null || email.isBlank()) {
            return error("Google no compartio email");
        }

        User user = googleId == null ? null : theUserRepository.getUserByGoogleId(googleId);
        if (user == null) {
            user = theUserRepository.getUserByEmail(email);
        }
        if (user == null) {
            user = new User();
            user.setEmail(email);
            user.setName(name);
            user.setPassword(passwordHashService.hashNew(UUID.randomUUID().toString()));
        }

        user.setGoogleId(googleId);
        user.setGoogleAvatarUrl(picture);
        theUserRepository.save(user);
        ensureDefaultCitizenRole(user);

        String token = theJwtService.generateToken(user, getRolesByUser(user));
        createSessionForToken(user, token);
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        return response;
    }

    public Map<String, Object> unlinkGoogle(String userId) {
        User user = theUserRepository.findById(userId).orElse(null);
        if (user == null) {
            return error("Usuario no encontrado");
        }
        user.setGoogleId(null);
        user.setGoogleAvatarUrl(null);
        theUserRepository.save(user);
        return Map.of("message", "Cuenta Google desvinculada");
    }

    public Map<String, Object> microsoftCallback(String code) {
        String accessToken = microsoftOAuthService.exchangeCodeForAccessToken(code);
        if (accessToken == null) {
            return error("No fue posible autenticar con Microsoft");
        }

        Map<String, Object> profile = microsoftOAuthService.getMicrosoftProfile(accessToken);
        if (profile == null) {
            return error("No fue posible obtener perfil de Microsoft");
        }

        String microsoftId = profile.get("id") == null ? null : profile.get("id").toString();
        String displayName = profile.get("displayName") == null ? null : profile.get("displayName").toString();
        String email = profile.get("mail") == null ? null : profile.get("mail").toString();
        if (email == null || email.isBlank()) {
            // En cuentas organizacionales, a veces viene aqui.
            email = profile.get("userPrincipalName") == null ? null : profile.get("userPrincipalName").toString();
        }

        if (email == null || email.isBlank()) {
            return error("Microsoft no compartio email");
        }

        User user = microsoftId == null ? null : theUserRepository.getUserByMicrosoftId(microsoftId);
        if (user == null) {
            user = theUserRepository.getUserByEmail(email);
        }
        if (user == null) {
            user = new User();
            user.setEmail(email);
            user.setName(displayName);
            user.setPassword(passwordHashService.hashNew(UUID.randomUUID().toString()));
        }

        user.setMicrosoftId(microsoftId);
        theUserRepository.save(user);
        ensureDefaultCitizenRole(user);

        String token = theJwtService.generateToken(user, getRolesByUser(user));
        createSessionForToken(user, token);
        return Map.of("token", token);
    }

    public Map<String, Object> unlinkMicrosoft(String userId) {
        User user = theUserRepository.findById(userId).orElse(null);
        if (user == null) {
            return error("Usuario no encontrado");
        }
        user.setMicrosoftId(null);
        user.setMicrosoftAvatarUrl(null);
        theUserRepository.save(user);
        return Map.of("message", "Cuenta Microsoft desvinculada");
    }

    private List<String> getRolesByUser(User user) {
        if (user == null || user.get_id() == null) {
            return List.of("USER");
        }
        List<UserRole> roles = theUserRoleRepository.findByUserId(user.get_id());
        if (roles == null || roles.isEmpty()) {
            return List.of("USER");
        }
        return roles.stream()
                .map(userRole -> userRole.getRole() == null ? "USER" : userRole.getRole().getName())
                .filter(Objects::nonNull)
                .toList();
    }

    private Map<String, Object> error(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", message);
        return response;
    }

    private String generateNumericCode(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@", 2);
        String local = parts[0];
        String domain = parts[1];
        String maskedLocal = local.length() <= 2 ? "***" : local.substring(0, 2) + "***";
        return maskedLocal + "@***." + domain.substring(Math.max(domain.lastIndexOf('.') + 1, 0));
    }

    // Se mantiene el logger por si se requiere diagnostico,
    // pero los flujos de correo ya usan EmailService (que tambien hace fallback a logs).
    private void logAccountCreated(String email, String fullName) {
        LOGGER.info("[MAIL] Cuenta creada para {} ({})", fullName, email);
    }

    /**
     * Para cuentas nuevas, asigna un rol base para que el usuario tenga permisos minimos.
     */
    private void ensureDefaultCitizenRole(User user) {
        if (user == null || user.get_id() == null) {
            return;
        }
        Role citizen = theRoleRepository.findByName("Ciudadano");
        if (citizen == null || citizen.getId() == null) {
            return;
        }
        UserRole existing = theUserRoleRepository.findByUserIdAndRoleId(user.get_id(), citizen.getId());
        if (existing != null) {
            return;
        }
        theUserRoleRepository.save(new UserRole(user, citizen));
    }

    private void createSessionForToken(User user, String token) {
        if (user == null || user.get_id() == null || token == null || token.isBlank()) {
            return;
        }
        Session s = new Session();
        s.setUser(user);
        s.setToken(token);
        s.setPartialAuth(false);
        s.setOtpVerified(true);
        s.setCreatedAt(new Date());
        s.setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs));
        theSessionRepository.save(s);
    }
}
