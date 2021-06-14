package com.platform.demo.repository;

import com.platform.demo.graphNode.StatementNode;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface StatementRepository extends Neo4jRepository<StatementNode, Long> {
//    @Query("create (a:Method{code=$code, startLine:{startLine}, endLine:{endLine}, isCFGNode:{isCFGNode}}) RETURN N ")
//    List<FileNode> addMethodNodes(@Param("code") String code,
//                                  @Param("startLine") int startLine,
//                                  @Param("endLine") int endLine,
//                                  @Param("isCFGNode") boolean isCFGNode);
}
