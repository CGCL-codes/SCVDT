package com.platform.demo.graphNode;

//import org.springframework.data.neo4j.core.schema.Id;
//import org.springframework.data.neo4j.core.schema.Node;

import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Property;

@NodeEntity(label = "METHOD")
@Data
@Builder
public class MethodNode{
    @Id
    @GeneratedValue
    private Long id;

    @Property(name = "code")
    private String code;

    @Property(name = "startLine")
    private int startLine;

    @Property(name = "endLine")
    private int endLine;

    @Property(name = "dirName")
    private String dirName;

    @Property(name = "filePath")
    private String filePath;

    public Long getId() {
        return id;
    }

    @Property(name = "classID")
    private Long classID;

//    public MethodNode(String code, String startLine, String endLine, Long id) {
//        this.code = code;
//        this.startLine = startLine;
//        this.endLine = endLine;
//        this.id = id;
//       // this.id = id;
//    }
//
//    public Long getId() {
//        return id;
//    }
//
//    public void setId(Long id) {
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


}


