package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface UserRoleRepository extends MongoRepository<UserRole, String> {

    @Query("{'user.$id': ?0}")
    List<UserRole> findByUserId(String userId);

    // DBRef a Role suele persistirse como { "$ref": "...", "$id": "..." }.
    @Query("{'role.$id': ?0}")
    List<UserRole> findByRoleId(String roleId);

    @Query("{'user.$id': ?0, 'role.$id': ?1}")
    UserRole findByUserIdAndRoleId(String userId, String roleId);
}
