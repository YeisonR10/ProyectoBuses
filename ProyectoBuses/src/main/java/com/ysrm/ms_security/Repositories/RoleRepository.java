package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface RoleRepository extends MongoRepository<Role, String> {
}
