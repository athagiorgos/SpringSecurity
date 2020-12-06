package com.gogos.demo.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectApplicationUserByUserName(String name);
}
