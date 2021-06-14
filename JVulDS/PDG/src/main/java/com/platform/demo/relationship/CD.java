package com.platform.demo.relationship;

import com.platform.demo.graphNode.FileNode;
import com.platform.demo.graphNode.MethodNode;
import com.platform.demo.graphNode.StatementNode;
import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.*;

@RelationshipEntity
@Data
@Builder
public class CD {
    @Id
    @GeneratedValue
    private Long id;

    @StartNode
    private StatementNode parent;

    @EndNode
    private StatementNode child;

    @Property(name = "message")
    private String message;
}
