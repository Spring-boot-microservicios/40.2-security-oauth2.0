package com.angelfg.security_oauth.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;
import java.math.BigInteger;

@Entity
@Table(name = "roles")
@Data
public class RoleEntity implements Serializable { // Serializable es opcional

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private BigInteger id;

    @Column(name = "role_name")
    private String name;

    private String description;

}
