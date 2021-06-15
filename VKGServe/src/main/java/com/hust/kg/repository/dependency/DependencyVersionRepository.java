package com.hust.kg.repository.dependency;

import com.hust.kg.entity.dependency.DependencyVersion;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.Repository;

import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/30 11:19
 * @Description:
 */
public interface DependencyVersionRepository extends Repository<DependencyVersion, Long> {
    @Query("match (n:DependencyVersion) return n limit 200")
    List<DependencyVersion> findAll();
}
