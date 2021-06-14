package com.platform.demo.repository;

import com.platform.demo.relationship.Enter;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface RelationshipRepositoryMToS extends Neo4jRepository<Enter, Long> {
}
