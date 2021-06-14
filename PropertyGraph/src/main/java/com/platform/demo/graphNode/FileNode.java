package com.platform.demo.graphNode;

import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Property;
//import org.springframework.data.neo4j.core.schema.GeneratedValue;
//import org.springframework.data.neo4j.core.schema.Id;
//import org.springframework.data.neo4j.core.schema.Node;
//import org.springframework.data.neo4j.core.schema.Property;
//改成class label
@NodeEntity(label = "CLASS")
@Data
@Builder
public class FileNode {
    @Id
    @GeneratedValue
    private Long id;

    @Property(name = "filePath")
    private String filePath;

    @Property(name = "code")
    private String code;


    public Long getId() {
        return id;
    }

    //    public void FileNode(String filePath, Long id){
//        this.filePath = filePath;
//        this.id = id;
//    }
//    public void setFilePath(String filePath) {
//        this.filePath = filePath;
//    }

    public String getFilePath() {
        return filePath;
    }
}
