package com.ysrm.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class User {
    @Id
    private String _id;
    private String name;
    private String lastName;
    private String email;
    private String password;

    // Campos para HU-006 (login social con GitHub)
    private String githubId;
    private String githubUsername;
    private String githubAvatarUrl;

    // Campos para HU-ENTR-1-004 (Google)
    private String googleId;
    private String googleAvatarUrl;

    // Campos para HU-ENTR-1-005 (Microsoft)
    private String microsoftId;
    private String microsoftAvatarUrl;

    public User(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }

    public User() {
    }
}
