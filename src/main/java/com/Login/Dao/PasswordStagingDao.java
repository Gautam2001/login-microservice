package com.Login.Dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Login.Entity.PasswordStagingEntity;

@Repository
public interface PasswordStagingDao extends JpaRepository<PasswordStagingEntity, Long> {

	Optional<PasswordStagingEntity> getUserByUsername(String username);

}
