package com.ysrm.ms_security.Services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailService.class);

    @Value("${mail.enabled:false}")
    private boolean mailEnabled;

    @Value("${mail.from:no-reply@sistema.com}")
    private String from;

    @Autowired(required = false)
    private JavaMailSender mailSender;

    public void sendAccountCreated(String email, String fullName) {
        send(email, "Cuenta creada", "Cuenta creada para: " + fullName + " (" + email + ")");
    }

    public void sendTwoFactorCode(String email, String code) {
        send(email, "Codigo de verificacion", "Su codigo 2FA es: " + code);
    }

    public void sendPasswordReset(String email, String resetUrl) {
        send(email, "Recuperacion de contrasena", "Use este enlace para restablecer su contrasena: " + resetUrl);
    }

    public void sendRolesChanged(String email, String detail) {
        send(email, "Cambios de roles/permisos", detail);
    }

    public void sendPermissionsChanged(String email, String roleName) {
        send(email, "Permisos actualizados", "Se actualizaron los permisos del rol: " + roleName);
    }

    private void send(String to, String subject, String body) {
        if (to == null || to.isBlank()) {
            return;
        }
        if (!mailEnabled || mailSender == null) {
            // Fallback: no rompe el flujo si no hay SMTP configurado.
            LOGGER.info("[MAIL] To={} Subject={} Body={}", to, subject, body);
            return;
        }
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(from);
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(body);
        mailSender.send(msg);
    }
}
