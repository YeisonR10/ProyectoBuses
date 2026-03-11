package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRoleRepository extends MongoRepository<UserRole,String> {
}
