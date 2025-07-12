package com.Login.Dao;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Login.Entity.UserAuthEntity;

@Repository
public interface UserAuthDao extends JpaRepository<UserAuthEntity, UUID> {

	Optional<UserAuthEntity> getUserByUsername(String username);

}
