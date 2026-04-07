package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface UserRepository extends MongoRepository<User, String> {

    @Query("{'email': ?0}")
    User getUserByEmail(String email);

    boolean existsByEmail(String email);

    @Query("{'githubId': ?0}")
    User getUserByGithubId(String githubId);

    @Query("{'googleId': ?0}")
    User getUserByGoogleId(String googleId);

    @Query("{'microsoftId': ?0}")
    User getUserByMicrosoftId(String microsoftId);

    @Query("{ $or: [ {'name': { $regex: ?0, $options: 'i' } }, {'email': { $regex: ?0, $options: 'i' } } ] }")
    List<User> searchByNameOrEmail(String q);
}
