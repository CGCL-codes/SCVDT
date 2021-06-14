package com.platform.demo.graphNode;

import lombok.Builder;
import lombok.Data;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Property;
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
    public String getFilePath() {
        return filePath;
    }
}
