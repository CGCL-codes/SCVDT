package com.hust.kg.repository.dependency;

import com.hust.kg.entity.dependency.Dependency;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.Repository;

import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/30 11:32
 * @Description:
 */
public interface DependencyRepository extends Repository<Dependency, Long> {
    @Query("match (n:Dependency) return n limit 200")
    List<Dependency> findAll();
}
