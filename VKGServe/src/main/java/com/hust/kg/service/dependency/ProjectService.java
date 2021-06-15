package com.hust.kg.service.dependency;

import com.hust.kg.entity.PathConfig;
import com.hust.kg.entity.dependency.Parent;
import com.hust.kg.entity.dependency.ProjectVersion;
import com.hust.kg.parse.ParseToJson;
import com.hust.kg.entity.dependency.Project;
import com.hust.kg.repository.dependency.ProjectRepository;
import com.hust.kg.service.CypherService;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.neo4j.driver.Driver;
import org.springframework.data.neo4j.core.DatabaseSelectionProvider;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.Properties;

/**
 * @Author wk
 * @Date 2021/03/30 10:51
 * @Description:
 */
@Service
public class ProjectService {
    private final ProjectRepository repository;

    private final Neo4jClient neo4jClient;

    private final Driver driver;

    private final DatabaseSelectionProvider databaseSelectionProvider;

    private final CypherService cypherService;

    public ProjectService(ProjectRepository repository, Neo4jClient neo4jClient, Driver driver, DatabaseSelectionProvider databaseSelectionProvider, CypherService cypherService) {
        this.repository = repository;
        this.neo4jClient = neo4jClient;
        this.driver = driver;
        this.databaseSelectionProvider = databaseSelectionProvider;
        this.cypherService = cypherService;
    }

    public String findAll(){
        List<Project> projects = this.repository.findAll();
        return ParseToJson.listToJson(projects, "Project");
    }

    public String fuzzyFind(String project){
        String cypher = "match p=(n:Project)-[]->(:Parent) where n.name=~'.*" + project + ".*' or n.artifact_id=~'.*" + project + ".*' return p";
        return cypherService.executeCypher(cypher);
    }

    public String addDependencyByPom(MultipartFile file, String software){
        try{
            String fileName = file.getOriginalFilename();
            File dest = new File(PathConfig.uploadPomPath + "/" + software + "/" + fileName);
            if(!dest.getParentFile().exists()){
                dest.getParentFile().mkdirs();
            }
            file.transferTo(dest);
            FileInputStream fileInputStream = new FileInputStream(dest);
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(fileInputStream);
            System.out.println(model);
            ProjectVersion projectVersion = new ProjectVersion(0L, model.getName(), model.getModelVersion(), model.getGroupId());
            System.out.println(projectVersion);
            Parent parent = new Parent(0L, model.getParent().getArtifactId(), model.getParent().getGroupId(), "null");
            System.out.println(parent);
            Project project = new Project(0L, software, model.getArtifactId(), model.getDescription(), model.getUrl());
            System.out.println(project);
            String cypher = "merge p=(:Project{name:'" + project.getName() +"',artifact_id:'" + project.getArtifactID() +"',description:'" + project.getDescription() +"',url:'"+ project.getUrl() +"'})-[:has]->" + "(:ProjectVersion{project_name:'"+ projectVersion.getProjectName() +"',version:'"+ projectVersion.getVersion() +"',group_id:'"+ projectVersion.getGroupID() +"'})";
            System.out.println(cypher);
            this.driver.session().run(cypher);
            Thread.sleep(100);
            List<Dependency> dependencies = model.getDependencyManagement().getDependencies();
            Properties properties =  model.getProperties();
            for(Dependency dependency:dependencies){
                String version = dependency.getVersion();
                if(version.charAt(0) == '$'){
                    version = version.substring(2, version.length()-1);
                    if(version.startsWith("pom.")){
                        version = version.substring(4, version.length());
                    }
                    version = properties.get(version).toString();
                }
                dependency.setVersion(version);
                cypher = "match(n:ProjectVersion{project_name:'"+ projectVersion.getProjectName() + "',version:'" + projectVersion.getVersion() + "',group_id:'" + projectVersion.getGroupID() + "'}) merge p=(n)-[:dependency]->(:DependencyVersion{project_name:'" + dependency.getArtifactId() + "',project_version:'" + dependency.getVersion() + "',group_id:'" + dependency.getGroupId() + "'})-[:`belongs to`]->(:Dependency{project_name:'" + dependency.getArtifactId() +"'})";
                System.out.println(cypher);
                this.driver.session().run(cypher);
            }
            return "添加成功";
        }catch (Exception e){
            e.printStackTrace();
        }
        return "添加失败";
    }
}
