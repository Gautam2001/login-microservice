package com.Login.Dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Login.Entity.SignupStagingEntity;

import jakarta.transaction.Transactional;

@Repository
public interface SignupStagingDao extends JpaRepository<SignupStagingEntity, Long> {

	Optional<SignupStagingEntity> getUserByUsername(String username);

	@Transactional
	int deleteByUsername(String username);

}
