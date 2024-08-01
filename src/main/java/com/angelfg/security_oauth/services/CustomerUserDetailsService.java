package com.angelfg.security_oauth.services;

import com.angelfg.security_oauth.entities.RoleEntity;
import com.angelfg.security_oauth.repositories.CustomerRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@AllArgsConstructor
public class CustomerUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    // Uso de UserDetailsService para realizar nuestra propia implementacion de seguridad
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.customerRepository.findByEmail(username)
            .map(customer -> {
                List<RoleEntity> roles = customer.getRoles();

                List<SimpleGrantedAuthority> authorities = roles
                        .stream()
                        .map(rol -> new SimpleGrantedAuthority(rol.getName()))
                        .toList();

                return new User(customer.getEmail(), customer.getPassword(), authorities);
            }).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

}
