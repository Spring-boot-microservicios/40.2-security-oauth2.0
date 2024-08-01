package com.angelfg.security_oauth.repositories;

import com.angelfg.security_oauth.entities.PartnerEntity;
import org.springframework.data.repository.CrudRepository;

import java.math.BigInteger;
import java.util.Optional;

public interface PartnerRepository extends CrudRepository<PartnerEntity, BigInteger> {
    Optional<PartnerEntity> findByClientId(String clientId);
}
