package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.PasswordResetToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

public interface PasswordResetTokenRepository extends MongoRepository<PasswordResetToken, String> {

    @Query("{'token': ?0}")
    PasswordResetToken getByToken(String token);
}

