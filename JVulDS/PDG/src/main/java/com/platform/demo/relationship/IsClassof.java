package com.platform.demo.relationship;

import com.platform.demo.graphNode.FileNode;
import com.platform.demo.graphNode.MethodNode;
import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.*;
//import org.springframework.data.neo4j.core.schema.GeneratedValue;
//import org.springframework.data.neo4j.core.schema.Id;
//import org.springframework.data.neo4j.core.schema.Relationship;

@RelationshipEntity
@Data
@Builder
public class IsClassof {
    @Id
    @GeneratedValue
    private Long id;

    @StartNode
    private FileNode parent;

    @EndNode
    private MethodNode child;



}
