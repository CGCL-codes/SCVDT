package com.hust.kg.entity.dependency;

import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;
import org.springframework.data.neo4j.core.schema.Property;

/**
 * @Author wk
 * @Date 2021/03/24 17:30
 * @Description:
 */
@Node
public class DependencyVersion {
    @Id
    private Long id;

    @Property(name = "project_name")
    private String projectName;

    @Property(name = "project_version")
    private String version;

    @Property(name = "group_id")
    private String groupID;

    public DependencyVersion(Long id, String projectName, String version, String groupID) {
        this.id = id;
        this.projectName = projectName;
        this.version = version;
        this.groupID = groupID;
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

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getGroupID() {
        return groupID;
    }

    public void setGroupID(String groupID) {
        this.groupID = groupID;
    }
}
