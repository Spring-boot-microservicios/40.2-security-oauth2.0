package com.angelfg.security_oauth.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

@Entity
@Table(name = "customers")
@Data
public class CustomerEntity implements Serializable { // Serializable es opcional

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private BigInteger id;

    private String email;

    @Column(name = "pwd")
    private String password;

    @OneToMany(fetch = FetchType.EAGER)
    @JoinColumn(name = "id_customer") // es el nombre del foreing key de la DB
    private List<RoleEntity> roles;

}
