package com.pm.userservice.mapper;

import com.pm.userservice.domain.auth.Role;
import com.pm.userservice.domain.user.UserProfile;
import com.pm.userservice.dto.user.UserResponseDTO;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface UserMapper {

    UserResponseDTO toDto(UserProfile entity);

    List<UserResponseDTO> toDtoList(List<UserProfile> entities);

    // MapStruct will call this for each Role inside the collection
    default String mapRole(Role role) {
        return role == null ? null : role.getCode();
    }
}


