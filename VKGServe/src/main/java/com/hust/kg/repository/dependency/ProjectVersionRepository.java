package com.hust.kg.repository.dependency;

import com.hust.kg.entity.dependency.ProjectVersion;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/30 10:19
 * @Description:
 */
public interface ProjectVersionRepository extends Repository<ProjectVersion, Long> {
    @Query("match (n:ProjectVersion) return n limit 200")
    List<ProjectVersion> findAll();

    @Query("match (n:ProjectVersion) where n.project_name=~ ('.*'+$project+'.*') return n")
    List<ProjectVersion> fuzzyFind(@Param("project")String project);
}
