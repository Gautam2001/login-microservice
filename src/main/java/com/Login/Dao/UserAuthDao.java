package com.Login.Dao;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Login.Entity.UserAuthEntity;
import com.Login.Entity.UserAuthEntity.Role;

@Repository
public interface UserAuthDao extends JpaRepository<UserAuthEntity, UUID> {

	Optional<UserAuthEntity> getUserByUsername(String username);
	
	Optional<UserAuthEntity> getUserByUsernameAndRole(String username, Role role);
	
	int countByRole(Role role);

}
