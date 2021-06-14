package com.platform.demo.repository;

import com.platform.demo.relationship.CD;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface RelationshipRepositoryCD extends Neo4jRepository<CD, Long> {
}
