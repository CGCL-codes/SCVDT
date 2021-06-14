package com.platform.demo.repository;

import com.platform.demo.graphNode.MyAstNode;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface AstRepository extends Neo4jRepository<MyAstNode, Long> {
}
