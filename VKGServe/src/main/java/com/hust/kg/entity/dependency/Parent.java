package com.hust.kg.entity.dependency;

import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;
import org.springframework.data.neo4j.core.schema.Property;

/**
 * @Author wk
 * @Date 2021/03/24 17:27
 * @Description:
 */
@Node
public class Parent {
    @Id
    private Long id;

    private String name;

    @Property(name = "group_id")
    private String groupID;

    private String description;

    public Parent(Long id, String name, String groupID, String description) {
        this.id = id;
        this.name = name;
        this.groupID = groupID;
        this.description = description;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGroupID() {
        return groupID;
    }

    public void setGroupID(String groupID) {
        this.groupID = groupID;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "Parent{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", groupID='" + groupID + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
