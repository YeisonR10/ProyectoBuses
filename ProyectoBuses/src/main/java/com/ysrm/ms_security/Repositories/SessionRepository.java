package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.Session;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

public interface SessionRepository extends MongoRepository<Session, String> {

    @Query("{'token': ?0}")
    Session getByToken(String token);
}
