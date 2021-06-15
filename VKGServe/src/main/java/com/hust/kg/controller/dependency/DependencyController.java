package com.hust.kg.controller.dependency;

import com.hust.kg.entity.dependency.Dependency;
import com.hust.kg.service.dependency.DependencyService;
import com.hust.kg.service.dependency.DependencyVersionService;
import com.hust.kg.service.dependency.ProjectService;
import com.hust.kg.service.dependency.ProjectVersionService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * @Author wk
 * @Date 2021/03/30 10:37
 * @Description:
 */
@RestController
public class DependencyController {
    private final ProjectVersionService projectVersionService;
    private final ProjectService projectService;
    private final DependencyVersionService dependencyVersionService;
    private final DependencyService dependencyService;

    public DependencyController(ProjectVersionService projectVersionService, ProjectService projectService, DependencyVersionService dependencyVersionService, DependencyService dependencyService) {
        this.projectVersionService = projectVersionService;
        this.projectService = projectService;
        this.dependencyVersionService = dependencyVersionService;
        this.dependencyService = dependencyService;
    }

    @RequestMapping("/projectVersion/all-top-200")
    public String findAllVersion(){
        return projectVersionService.findAll();
    }

    @RequestMapping("/projectVersion")
    public String fuzzyFindProjectVersion(@RequestParam("project")String project){
        return projectVersionService.fuzzyFindByName(project);
    }

    @RequestMapping("/project/all")
    public String findAllProject(){
        return projectService.findAll();
    }

    @RequestMapping("/project")
    public String fuzzyFindProject(@RequestParam("project")String project){
        return projectService.fuzzyFind(project);
    }

    @RequestMapping("/dependencyVersion/all-top-200")
    public String findAllDependencyVersion(){
        return dependencyVersionService.findAll();
    }

    @RequestMapping("/dependency/all-top-200")
    public String findAllDependency(){
        return dependencyService.findAll();
    }

    @RequestMapping(value = "/addPom", method = RequestMethod.POST)
    public String addPom(@RequestParam("file")MultipartFile file, @RequestParam("software")String software){
        return projectService.addDependencyByPom(file, software);
    }
}
