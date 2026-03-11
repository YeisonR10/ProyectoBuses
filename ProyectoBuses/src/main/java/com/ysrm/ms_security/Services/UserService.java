package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.Profile;
import com.ysrm.ms_security.Models.Session;
import com.ysrm.ms_security.Models.User;
import com.ysrm.ms_security.Repositories.ProfileRepository;
import com.ysrm.ms_security.Repositories.SessionRepository;
import com.ysrm.ms_security.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private ProfileRepository theProfileRepository;

    @Autowired
    private SessionRepository theSessionRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    public List<User> find() {
        return this.theUserRepository.findAll();
    }

    public User findById(String id) {
        return this.theUserRepository.findById(id).orElse(null);
    }

    public User create(User newUser) {
        newUser.setPassword(theEncryptionService.convertSHA256(newUser.getPassword()));
        return this.theUserRepository.save(newUser);
    }

    public User update(String id, User newUser) {
        User actualUser = this.theUserRepository.findById(id).orElse(null);
        if (actualUser != null) {
            actualUser.setName(newUser.getName());
            actualUser.setLastName(newUser.getLastName());
            actualUser.setEmail(newUser.getEmail());
            if (newUser.getPassword() != null && !newUser.getPassword().isBlank()) {
                actualUser.setPassword(theEncryptionService.convertSHA256(newUser.getPassword()));
            }
            this.theUserRepository.save(actualUser);
            return actualUser;
        }
        return null;
    }

    public void delete(String id) {
        this.theUserRepository.findById(id).ifPresent(this.theUserRepository::delete);
    }

    /**
     * Permite asociar un usuario y un perfil. Para que funcione ambos
     * ya deben existir en la base de datos.
     *
     * @param userId identificador del usuario
     * @param profileId identificador del perfil
     * @return true si la asociacion fue realizada; false si no existe el usuario o el perfil
     */
    public boolean addProfile(String userId, String profileId) {
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Profile theProfile = this.theProfileRepository.findById(profileId).orElse(null);
        if (theUser != null && theProfile != null) {
            theProfile.setUser(theUser);
            this.theProfileRepository.save(theProfile);
            return true;
        }
        return false;
    }

    public boolean removeProfile(String userId, String profileId) {
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Profile theProfile = this.theProfileRepository.findById(profileId).orElse(null);
        if (theUser != null && theProfile != null) {
            theProfile.setUser(null);
            this.theProfileRepository.save(theProfile);
            return true;
        }
        return false;
    }

    /**
     * Permite asociar un usuario y una sesion. Para que funcione ambos
     * ya deben existir en la base de datos.
     *
     * @param userId identificador del usuario
     * @param sessionId identificador de la sesion
     * @return true si la asociacion fue realizada; false si no existe el usuario o la sesion
     */
    public boolean addSession(String userId, String sessionId) {
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Session theSession = this.theSessionRepository.findById(sessionId).orElse(null);
        if (theUser != null && theSession != null) {
            theSession.setUser(theUser);
            this.theSessionRepository.save(theSession);
            return true;
        }
        return false;
    }

    public boolean removeSession(String userId, String sessionId) {
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Session theSession = this.theSessionRepository.findById(sessionId).orElse(null);
        if (theUser != null && theSession != null) {
            theSession.setUser(null);
            this.theSessionRepository.save(theSession);
            return true;
        }
        return false;
    }
}
