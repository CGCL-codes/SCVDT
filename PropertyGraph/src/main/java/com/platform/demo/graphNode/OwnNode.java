package com.platform.demo.graphNode;

import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;
//import org.springframework.data.neo4j.core.schema.Id;
//import org.springframework.data.neo4j.core.schema.Node;

@NodeEntity
public class OwnNode {
    @Id
    private int id;

    private String code;
    private int startLine;
    private int endLine;

    public OwnNode(String code, int startLine, int endLine,int id) {
        this.code = code;
        this.startLine = startLine;
        this.endLine = endLine;
        this.id = id;
    }

    public OwnNode(String code, int startLine, int endLine) {
        this.code = code;
        this.startLine = startLine;
        this.endLine = endLine;
    }

    public int getEndLine() {
        return endLine;
    }

    public int getStartLine() {
        return startLine;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code){
        this.code = code;
    }

    public void setStartLine(int l){
        this.startLine = l;
    }

    public void setEndLine(int l){
        this.endLine = l;
    }
}
