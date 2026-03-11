package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

public interface UserRepository extends MongoRepository<User, String> {

    @Query("{'email': ?0}")
    User getUserByEmail(String email);

    boolean existsByEmail(String email);

    @Query("{'githubId': ?0}")
    User getUserByGithubId(String githubId);
}
