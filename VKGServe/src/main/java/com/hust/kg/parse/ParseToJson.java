package com.hust.kg.parse;

import com.hust.kg.entity.dependency.Dependency;
import com.hust.kg.entity.dependency.DependencyVersion;
import com.hust.kg.entity.dependency.Project;
import com.hust.kg.entity.dependency.ProjectVersion;
import com.hust.kg.entity.vulnerability.*;
import com.hust.kg.repository.vulnerability.SoftwareVendorRepository;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author wk
 * @Date 2021/03/29 11:32
 * @Description:
 */
public class ParseToJson {
    public static String listToJson(List list, String type){
        StringBuffer nodes = new StringBuffer();
        nodes.append("\"nodes\":[");
        int num = 0;
        switch (type){
            case "Vulnerability":
                for(Object node:list)
                {
                    Vulnerability vulnerability = (Vulnerability)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + vulnerability.getId() + ",");
                    nodes.append("\"labels\":[\"Vulnerability\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"cve_id\":\"" + vulnerability.getCveID() + "\",");
                    String description = vulnerability.getDescription();
                    description = description.replace("\\","\\\\").replace("\"","\\\"");
                    nodes.append("\"description\":\"" + description + "\",");
                    nodes.append("\"link\":\"" + vulnerability.getLink() + "\",");
                    nodes.append("\"author\":\"" + vulnerability.getAuthor() + "\",");
                    nodes.append("\"published_time\":\"" + vulnerability.getPublishedTime() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "VulnType":
                for(Object node:list)
                {
                    VulnType vulnType = (VulnType)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + vulnType.getId() + ",");
                    nodes.append("\"labels\":[\"VulnType\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"cwe_id\":\"" + vulnType.getCweID() + "\",");
                    String description = vulnType.getDescription();
                    description = description.replace("\\","\\\\").replace("\"","\\\"");
                    nodes.append("\"description\":\"" + description + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "CVSS":
                for(Object node:list)
                {
                    CVSS cvss = (CVSS)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + cvss.getId() + ",");
                    nodes.append("\"labels\":[\"CVSS\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"base_score\":\"" + cvss.getBaseScore() + "\",");
                    nodes.append("\"vector\":\"" + cvss.getVector() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "Exploit":
                for(Object node:list)
                {
                    Exploit exploit = (Exploit)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + exploit.getId() + ",");
                    nodes.append("\"labels\":[\"Exploit\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"code_file\":\"" + exploit.getCodeFile() + "\",");
                    String description = exploit.getDescription();
                    description = description.replace("\\","\\\\").replace("\"","\\\"");
                    nodes.append("\"description\":\"" + description + "\",");
                    nodes.append("\"url\":\"" + exploit.getUrl() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "VulnPatch":
                for(Object node:list)
                {
                    VulnPatch vulnPatch = (VulnPatch)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + vulnPatch.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"cve_id\":\"" + vulnPatch.getCveID() + "\",");
                    nodes.append("\"software\":\"" + vulnPatch.getSoftware() + "\",");
                    nodes.append("\"diff_file\":\"" + vulnPatch.getDiffFile() + "\",");
                    nodes.append("\"diff_url\":\"" + vulnPatch.getDiffUrl() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "SoftwareVersion":
                for(Object node:list)
                {
                    SoftwareVersion softwareVersion = (SoftwareVersion)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + softwareVersion.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"software_name\":\"" + softwareVersion.getSoftwareName() + "\",");
                    nodes.append("\"version\":\"" + softwareVersion.getVersion() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "Software":
                for(Object node:list)
                {
                    Software software = (Software)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + software.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"software_name\":\"" + software.getSoftwareName() + "\",");
                    nodes.append("\"vendor\":\"" + software.getVendor() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "SoftwareVendor":
                for(Object node:list)
                {
                    SoftwareVendor vendor = (SoftwareVendor)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + vendor.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"vendor_name\":\"" + vendor.getVendorName() + "\",");
                    nodes.append("\"url\":\"" + vendor.getUrl() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "ProjectVersion":
                for(Object node:list)
                {
                    ProjectVersion projectVersion = (ProjectVersion)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + projectVersion.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"project_name\":\"" + projectVersion.getProjectName() + "\",");
                    nodes.append("\"version\":\"" + projectVersion.getVersion() + "\",");
                    nodes.append("\"group_id\":\"" + projectVersion.getGroupID() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "Project":
                for(Object node:list)
                {
                    Project project = (Project)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + project.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"name\":\"" + project.getName() + "\",");
                    nodes.append("\"artifact_id\":\"" + project.getArtifactID() + "\",");
                    String description = project.getDescription();
                    description = description.replace("\\","\\\\").replace("\"","\\\"");
                    nodes.append("\"description\":\"" + description + "\",");
                    nodes.append("\"url\":\"" + project.getUrl() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "DependencyVersion":
                for(Object node:list)
                {
                    DependencyVersion dependencyVersion = (DependencyVersion)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + dependencyVersion.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"project_name\":\"" + dependencyVersion.getProjectName() + "\",");
                    nodes.append("\"project_version\":\"" + dependencyVersion.getVersion() + "\",");
                    nodes.append("\"group_id\":\"" + dependencyVersion.getGroupID() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            case "Dependency":
                for(Object node:list)
                {
                    Dependency dependency = (Dependency)node;
                    if(num > 0){
                        nodes.append(",");
                    }
                    nodes.append("{");
                    nodes.append("\"id\":" + dependency.getId() + ",");
                    nodes.append("\"labels\":[\"" + type + "\"],");
                    nodes.append("\"properties\":{");
                    nodes.append("\"project_name\":\"" + dependency.getProjectName() + "\"");
                    nodes.append("}");
                    nodes.append("}");
                    num++;
                }
                break;
            default:
                break;
        }
        nodes.append("]");
        return "{\"results\":[{\"data\":[{\"graph\":{" + nodes.toString() + ",\"relationships\":[]}}]}]}";
    }
}
