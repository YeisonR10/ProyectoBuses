package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface UserRoleRepository extends MongoRepository<UserRole, String> {

    @Query("{'user._id': ?0}")
    List<UserRole> findByUserId(String userId);
}
