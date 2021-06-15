package com.hust.kg.repository.dependency;

import com.hust.kg.entity.dependency.Project;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/30 10:48
 * @Description:
 */
public interface ProjectRepository extends Repository<Project, Long> {
    @Query("match (n:Project) return n limit 200")
    List<Project> findAll();
}
