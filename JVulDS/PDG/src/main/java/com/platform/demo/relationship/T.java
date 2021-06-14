package com.platform.demo.relationship;

import com.platform.demo.graphNode.MyAstNode;
import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.*;

@RelationshipEntity
@Data
@Builder
public class T {
    @Id
    @GeneratedValue
    private Long id;

    @StartNode
    private MyAstNode parent;

    @EndNode
    private MyAstNode child;
}
