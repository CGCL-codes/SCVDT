package com.platform.demo.repository;

import com.platform.demo.relationship.MethodTo;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface RelationShipRepositoryMethodTo extends Neo4jRepository<MethodTo, Long> {

}
