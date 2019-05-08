package hu.szakdolgozat.szakdolgozat.repository;

import hu.szakdolgozat.szakdolgozat.model.Role;
import hu.szakdolgozat.szakdolgozat.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(RoleName roleName);

}
