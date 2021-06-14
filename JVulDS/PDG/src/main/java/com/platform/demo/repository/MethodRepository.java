package com.platform.demo.repository;

import com.platform.demo.graphNode.MethodNode;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface MethodRepository extends Neo4jRepository<MethodNode, Long> {
//    @Query("create (a:Method{code:{code}, startLine:{startLine}, endLine:{endLine}}) RETURN N ")
//    List<FileNode> addMethodNodes(@Param("code") String code,
//                                  @Param("startLine") int startLine,
//                                  @Param("endLine") int endLine);
}
