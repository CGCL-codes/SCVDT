package com.platform.demo.graphNode;

import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.*;

@NodeEntity(label = "ast")
@Data
@Builder
public class MyAstNode {
    @Id
    @GeneratedValue
    private Long id;

    @Property(name = "text")
    private String text;

    @Property(name = "category")
    private String category;

    @Property(name = "startLine")
    private String startLine;

    @Property(name = "endLine")
    private String endLine;

    @Relationship
    private String r;
}
