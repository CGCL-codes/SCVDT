package com.platform.demo.repository;

import com.platform.demo.graphNode.FileNode;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface FileRepository extends Neo4jRepository<FileNode,Long>{
//    @Query("create (a:File{filePath:{filePath}}) RETURN N ")
//    List<FileNode> addFileNodes(@Param("filePath") String filePath);


}
