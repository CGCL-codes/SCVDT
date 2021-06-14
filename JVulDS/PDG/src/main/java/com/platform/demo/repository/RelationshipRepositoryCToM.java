package com.platform.demo.repository;

import com.platform.demo.relationship.IsClassof;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RelationshipRepositoryCToM extends Neo4jRepository<IsClassof, Long> {

}
