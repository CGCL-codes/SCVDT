package com.hust.kg.entity.dependency;

import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;
import org.springframework.data.neo4j.core.schema.Property;

/**
 * @Author wk
 * @Date 2021/03/24 17:29
 * @Description:
 */
@Node
public class Dependency {
    @Id
    private Long id;

    @Property(name = "project_name")
    private String projectName;

    public Dependency(Long id, String projectName) {
        this.id = id;
        this.projectName = projectName;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }
}
