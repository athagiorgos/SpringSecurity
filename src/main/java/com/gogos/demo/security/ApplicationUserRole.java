package com.gogos.demo.security;

import com.google.common.collect.Sets;

import java.util.Set;

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
}
