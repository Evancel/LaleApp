package com.pm.userservice.domain.auth;

import com.pm.userservice.domain.user.UserProfile;
import jakarta.persistence.*;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name="roles", uniqueConstraints=@UniqueConstraint(name="uk_role_name", columnNames="code"))
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    Long id;
    @Column(nullable=false)
    private String code;
    @Column
    private String displayName;

    @ManyToMany(mappedBy = "roles")
    private List<UserProfile> users;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "roles_privileges",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "privilege_id"))
    private Set<Privilege> privileges = new LinkedHashSet<>();

    public Long getId() {
        return id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public List<UserProfile> getUsers() {
        return users;
    }

    public void setUsers(List<UserProfile> users) {
        this.users = users;
    }

    public Set<Privilege> getPrivileges() {
        return privileges;
    }

    public void setPrivileges(Set<Privilege> privileges) {
        this.privileges = privileges;
    }

    @Override
    public String toString() {
        return "Role{" +
                "code='" + code + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role other = (Role) o;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        // class hash ensures stable hash before id is assigned
        return getClass().hashCode();
    }
}
