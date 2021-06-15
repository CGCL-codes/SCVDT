package com.hust.kg.service.dependency;

import com.hust.kg.parse.ParseToJson;
import com.hust.kg.entity.dependency.Dependency;
import com.hust.kg.repository.dependency.DependencyRepository;
import com.hust.kg.service.CypherService;
import org.neo4j.driver.Driver;
import org.springframework.data.neo4j.core.DatabaseSelectionProvider;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/30 11:33
 * @Description:
 */
@Service
public class DependencyService {
    private final DependencyRepository repository;

    private final Neo4jClient neo4jClient;

    private final Driver driver;

    private final DatabaseSelectionProvider databaseSelectionProvider;

    private final CypherService cypherService;

    public DependencyService(DependencyRepository repository, Neo4jClient neo4jClient, Driver driver, DatabaseSelectionProvider databaseSelectionProvider, CypherService cypherService) {
        this.repository = repository;
        this.neo4jClient = neo4jClient;
        this.driver = driver;
        this.databaseSelectionProvider = databaseSelectionProvider;
        this.cypherService = cypherService;
    }

    public String findAll(){
        List<Dependency> dependencies = this.repository.findAll();
        return ParseToJson.listToJson(dependencies, "Dependency");
    }
}
