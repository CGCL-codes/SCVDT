package com.platform.demo.repository;

import com.platform.demo.relationship.FlowsTo;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface RelationshipRepositoryED extends Neo4jRepository<FlowsTo, Long> {
}
