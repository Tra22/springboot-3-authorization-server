package com.tra21.authorization_server.models;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@EqualsAndHashCode(callSuper = false)
@Entity
@Table(name = "users_")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 8219891288652008200L;
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;
    @Column(name = "email", length = 80, unique = true, nullable = false)
    private String email;

    @Column(name = "email_verified")
    private Boolean emailVerified;

    @Column(name = "username", unique = true, nullable = false)
    private String username;

    @Column(name = "preferred_username")
    private String preferredUsername;

    @Column(name = "password")
    private String password;

    @Column(name = "name")
    private String name;

    @Column(name = "unsigned_name")
    private String unsignedName;

    @Column(name = "given_name")
    private String givenName;

    @Column(name = "middle_name")
    private String middleName;

    @Column(name = "family_name")
    private String familyName;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "profile")
    private String profile;

    @Column(name = "picture", length = 1000)
    private String picture;

    @Column(name = "website", length = 200)
    private String website;

    @Column(name = "gender", length = 10)
    private String gender;

    @Column(name = "birthdate")
    private LocalDate birthdate;

    @Column(name = "zone_info")
    private String zoneInfo;

    @Column(name = "locale")
    private String locale;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "phone_number_verified")
    private Boolean phoneNumberVerified;

    @Column(name = "enabled")
    private Boolean enabled;

    @Column(name = "acc_locked")
    private Boolean accLocked;

    @Column(name = "acc_expired")
    private Boolean accExpired;

    @Column(name = "creds_expired")
    private Boolean credsExpired;
    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(name = "user_authorities",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id", referencedColumnName = "id"))
    private Set<Authority> authorities = new HashSet<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(authorities == null) return new ArrayList<>();
        return authorities.stream().map(item -> new SimpleGrantedAuthority(item.getName())).collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return !this.accExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.accLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !this.credsExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
