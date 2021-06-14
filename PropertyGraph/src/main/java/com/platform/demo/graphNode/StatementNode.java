package com.platform.demo.graphNode;

import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Property;
//import org.springframework.data.neo4j.core.schema.Node;

@NodeEntity(label = "EXPRESSION")
@Data
@Builder
public class StatementNode{

    @Id
    @GeneratedValue
    private Long id;

    @Property(name = "isCFGNode")
    private boolean isCFGNode;

    @Property(name = "code")
    private String code;

    @Property(name = "startLine")
    private int startLine;

    @Property(name = "endLine")
    private int endLine;

    @Property(name = "type")
    private int type;

    @Property(name = "methodID")
    private Long methodID;

//    public StatementNode(String code, int startLine, int endLine, int id, boolean isCFGNode) {
//        this.code = code;
//        this.startLine = startLine;
//        this.endLine = endLine;
//        this.id = id;
//        this.isCFGNode = isCFGNode;
//        // this.id = id;
//    }

//    public int getId() {
//        return id;
//    }
//
//    public void setId(int id) {
//        this.id = id;
//    }
//
//    public String getCode() {
//        return code;
//    }
//
//    public void setCode(String code) {
//        this.code = code;
//    }
//
//    public int getStartLine() {
//        return startLine;
//    }
//
//    public void setStartLine(int startLine) {
//        this.startLine = startLine;
//    }
//
//    public int getEndLine() {
//        return endLine;
//    }
//
//    public void setEndLine(int endLine) {
//        this.endLine = endLine;
//    }
//
//    public boolean isCFGNode() {
//        return isCFGNode;
//    }
//
//    public void setCFGNode(boolean CFGNode) {
//        isCFGNode = CFGNode;
//    }
}
