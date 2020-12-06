package com.gogos.demo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.gogos.demo.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {

    // student has none permissions
    STUDENT(Sets.newHashSet()),
    // admins has all permissions
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    // trainee role
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {

        // creating a stream so every permission to be inserted gets mapped to a SimpleGrantedAuthority Object
        Set<SimpleGrantedAuthority> permissions = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());

        // insert permissions to Set<> permissions
        permissions.add(new SimpleGrantedAuthority("ROLE_"+ this.name()));
        return permissions;
    }
}
