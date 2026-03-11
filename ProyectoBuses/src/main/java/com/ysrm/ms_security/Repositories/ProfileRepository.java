package com.ysrm.ms_security.Repositories;

import com.ysrm.ms_security.Models.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface ProfileRepository extends MongoRepository<Profile,String> {

}
