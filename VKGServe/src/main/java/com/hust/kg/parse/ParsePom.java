package com.hust.kg.parse;

import com.hust.kg.entity.dependency.Parent;
import com.hust.kg.entity.dependency.Project;
import com.hust.kg.entity.dependency.ProjectVersion;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.Properties;

/**
 * @Author wk
 * @Date 2021/03/31 17:15
 * @Description:
 */
public class ParsePom {
    public static void main(String[] args) {
        try {
            FileInputStream fileInputStream = new FileInputStream(new File("D:\\学习\\研究生\\毕业设计\\data\\dependencies\\hive\\release-2.3.2.xml"));
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(fileInputStream);
            System.out.println(model);
            ProjectVersion projectVersion = new ProjectVersion(0L, model.getName(), model.getModelVersion(), model.getGroupId());
            System.out.println(projectVersion);
            Parent parent = new Parent(0L, model.getParent().getArtifactId(), model.getParent().getGroupId(), "null");
            System.out.println(parent);
            Project project = new Project(0L, model.getName(), model.getArtifactId(), model.getDescription(), model.getUrl());
            System.out.println(project);
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
                System.out.println(dependency);
            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
