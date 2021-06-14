package com.platform.demo.repository;

import com.platform.demo.graphNode.StatementNode;
import com.platform.demo.relationship.T;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface RelationshipRepositoryT extends Neo4jRepository<T, Long>{

}
