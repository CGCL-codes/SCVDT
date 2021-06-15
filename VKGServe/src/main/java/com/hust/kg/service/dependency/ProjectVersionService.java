package com.hust.kg.service.dependency;

import com.hust.kg.parse.ParseToJson;
import com.hust.kg.entity.dependency.ProjectVersion;
import com.hust.kg.repository.dependency.ProjectVersionRepository;
import com.hust.kg.service.CypherService;
import org.neo4j.driver.Driver;
import org.springframework.data.neo4j.core.DatabaseSelectionProvider;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/30 10:30
 * @Description:
 */
@Service
public class ProjectVersionService {
    private final ProjectVersionRepository repository;

    private final Neo4jClient neo4jClient;

    private final Driver driver;

    private final DatabaseSelectionProvider databaseSelectionProvider;

    private final CypherService cypherService;

    public ProjectVersionService(ProjectVersionRepository repository, Neo4jClient neo4jClient, Driver driver, DatabaseSelectionProvider databaseSelectionProvider, CypherService cypherService) {
        this.repository = repository;
        this.neo4jClient = neo4jClient;
        this.driver = driver;
        this.databaseSelectionProvider = databaseSelectionProvider;
        this.cypherService = cypherService;
    }

    public String findAll(){
        List<ProjectVersion> projectVersions = this.repository.findAll();
        return ParseToJson.listToJson(projectVersions, "ProjectVersion");
    }

    public String fuzzyFindByName(String project){
        List<ProjectVersion> projectVersions = this.repository.fuzzyFind(project);
        return ParseToJson.listToJson(projectVersions, "ProjectVersion");
    }
}
