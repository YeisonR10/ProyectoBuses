package com.ysrm.ms_security.Repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import com.ysrm.ms_security.Models.User;
import org.springframework.data.mongodb.repository.Query;

public interface UserRepository extends MongoRepository<User,String> {

    @Query("{'email': ?0}")
    public User getUserByEmail(String email);
}
