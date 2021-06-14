package com.platform.demo.repository;

import com.platform.demo.relationship.DD;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface RelationshipRepositoryDD extends Neo4jRepository<DD, Long> {
}
