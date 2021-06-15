import os
import traceback
import re
from py2neo import Graph

from graph_process.database import add_project, query_project, query_project_version, add_project_version, add_relation, \
    query_parent, add_parent, query_dependency, query_dependency_version, add_dependency, add_dependency_version, \
    query_all_project_version, query_software_version, query_version_to_project, fuzzy_query_software_version

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from common.config import LOG_DIR, DEPENDENCY_DIR
from common.io import write_log
from common.models import Project, Software


# 获取所有pom.xml文件中的parent标签
def get_parent():
    data = set()
    for path, dirs, files in os.walk(DEPENDENCY_DIR):
        for file_name in files:
            if not file_name.endswith('.xml'):
                continue
            file_path = os.path.join(path, file_name)
            # print(file_path)
            try:
                root = ET.parse(file_path).getroot()
                POM_NS = '{http://maven.apache.org/POM/4.0.0}'
                for child in root.findall('%sparent' % (POM_NS)):
                    # artifactId 唯一标识一个项目
                    project_name = child.find('%sartifactId' % (POM_NS))
                    if project_name is not None:
                        project_name = project_name.text.strip()
                    else:
                        project_name = ''
                    # if len(child.findall('%sname' %(POM_NS))) != 0:
                    #     project_name = child.find('%sname' %(POM_NS)).text.strip()
                    project_name = parsePropertyName(root, project_name)
                    group_id = child.find('%sgroupId' % (POM_NS))
                    if group_id is not None:
                        group_id = group_id.text.strip()
                    else:
                        group_id = ''
                    group_id = parsePropertyName(root, group_id)
                    # print(project_name, group_id)
                    data.add((project_name, group_id))
            except Exception as e:
                print(file_path, e)
                traceback.print_exc()
    for item in data:
        print(item)


def getProjectName():
    baseDir = r'D:\学习\研究生\攻防自动化\漏洞数据库\Java漏洞数据\poms'
    os.chdir(baseDir)
    softwares = os.listdir(baseDir)
    Set = []
    project_names = {}
    for software in softwares:
        filePath = "{0}\\{1}".format(baseDir, software)
        os.chdir(filePath)
        # print(os.path.getsize(filePath))
        if software not in Set:
            Set.append(software)
            project_names[software] = []
        for list in os.listdir(filePath):
            # print('[+] Process ' + software + ' ' + list)
            if not list.endswith(".xml"):
                continue
            try:
                root = ET.parse(list).getroot()
                POM_NS = '{http://maven.apache.org/POM/4.0.0}'
                # 1
                # 获取当前项目的基本信息
                # 以artifactId作为项目名，唯一标记一个项目结点
                project_name = root.find('%sartifactId' % (POM_NS))
                if project_name is not None:
                    project_name = project_name.text.strip()
                else:
                    project_name = ''
                project_name = parsePropertyName(root, project_name)
                # print(project_name)
                if project_name not in project_names[software]:
                    project_names[software].append(project_name)
            except:
                continue
    for (k, v) in project_names.items():
        print(k + '\t' + '\t'.join(v))


def preprocess():
    file_path = r'{0}/{1}'.format(DEPENDENCY_DIR, '命名对齐.txt')
    file = open(file_path, 'r')
    project_software = dict()
    for item in file.readlines():
        item_splits = item.strip().split()
        project_name = item_splits[0]
        project_software[project_name] = []
        for i in range(1, len(item_splits)):
            project_software[project_name].append(item_splits[i])
    return project_software


project_software_dict = preprocess()
def parse_pom(software, fileName):
    if not fileName.endswith(".xml"):
        return {}
    print('[+] Parse the pom file: {0}'.format(fileName))
    try:
        root = ET.parse(fileName).getroot()
        POM_NS = '{http://maven.apache.org/POM/4.0.0}'
        project = Project()
        # 1
        graph = Graph('http://localhost:7474/', auth=('neo4j', '123456'))
        # 获取当前项目的基本信息
        artifact_id = root.find('%sartifactId' % (POM_NS))
        if artifact_id is not None:
            artifact_id = artifact_id.text.strip()
            if artifact_id == 'parent':
                artifact_id = software
        else:
            artifact_id = ''
        if len(root.findall('%sname' % (POM_NS))) != 0:
            project_name = root.find('%sname' % (POM_NS)).text.strip()
            if project_name == 'parent':
                project_name = software
        else:
            project_name = software
        project_name = parsePropertyName(root, project_name)
        version = root.find('%sversion' % (POM_NS))
        if version is not None:
            version = version.text.strip()
        else:
            version = ''
        version = parsePropertyName(root, version)
        group_id = root.find('%sgroupId' % (POM_NS))
        if group_id is not None:
            group_id = group_id.text.strip()
        else:
            group_id = ''
        group_id = parsePropertyName(root, group_id)
        project_url = root.find('%surl' % (POM_NS))
        if project_url is not None:
            project_url = project_url.text.strip()
        else:
            project_url = ''
        project_url = parsePropertyName(root, project_url)
        description = root.find('%sdescription' % (POM_NS))
        if description is not None:
            description = " ".join(description.text.split())
        else:
            description = ''
        description = parsePropertyName(root, description)
        project.setName(project_name)
        project.setArtifactId(artifact_id)
        project.setUrl(project_url)
        project.setVersion(version)
        project.setGroupId(group_id)
        project.setDescription(description)
        # print('Project:',project)
        # 2
        project_node = query_project(project)
        if project_node is None:
            project_node = add_project(project)
        else:
            flag = False
            if len(project_node['description']) == 0:
                project_node['description'] = project.description
                flag = True
            if len(project_node['url']) == 0:
                project_node['url'] = project.url
                flag = True
            if flag:
                graph.push(project_node)
        version_node = query_project_version(project)
        if version_node is None:
            version_node = add_project_version(project)
        else:
            return
        add_relation(project_node, 'has', version_node)
        # 获取当前项目的父项目信息
        parents = []
        for child in root.findall('%sparent' % (POM_NS)):
            parent_project = Project()
            # artifactId 唯一标识一个项目
            project_name = child.find('%sartifactId' % (POM_NS))
            if project_name is not None:
                project_name = project_name.text.strip()
            else:
                project_name = ''
            # if len(child.findall('%sname' %(POM_NS))) != 0:
            #     project_name = child.find('%sname' %(POM_NS)).text.strip()
            project_name = parsePropertyName(root, project_name)
            version = child.find('%sversion' % (POM_NS))
            if version is not None:
                version = version.text.strip()
            else:
                version = ''
            version = parsePropertyName(root, version)
            group_id = child.find('%sgroupId' % (POM_NS))
            if group_id is not None:
                group_id = group_id.text.strip()
            else:
                group_id = ''
            group_id = parsePropertyName(root, group_id)
            parent_project.setName(project_name)
            parent_project.setVersion(version)
            parent_project.setGroupId(group_id)
            parents.append(parent_project)
        for parent in parents:
            # print('Parent:',parent)
            # 3
            parent_node = query_parent(parent)
            if parent_node is None:
                parent_node = add_parent(parent)
            # 是否会重复
            add_relation(project_node, 'belong to', parent_node)
        dependencies = []
        dependencyManagement = root.find('%sdependencyManagement' % (POM_NS))
        if dependencyManagement is None:
            print("This xml file doesn't exist dependencyManagement.")
            return
        for dependency in dependencyManagement.find('%sdependencies' % (POM_NS)).findall('%sdependency' % (POM_NS)):
            dependency_node = Project()
            dependency_project_name = dependency.find('%sartifactId' % (POM_NS))
            if dependency_project_name is not None:
                dependency_project_name = dependency_project_name.text.strip()
            if len(dependency.findall('%sname' % (POM_NS))) != 0:
                dependency_project_name = dependency.find('%sname' % (POM_NS)).text.strip()
            # print('pure_name: ' + dependency_project_name)
            dependency_project_name = parsePropertyName(root, dependency_project_name)
            # print(dependency_project_name)
            dependency_group_id = dependency.find('%sgroupId' % (POM_NS))
            if dependency_group_id is not None:
                dependency_group_id = dependency_group_id.text.strip()
            # print('pure_groupid: ' + dependency_group_id)
            dependency_group_id = parsePropertyName(root, dependency_group_id)
            dependency_version = dependency.find('%sversion' % (POM_NS))
            if dependency_version is not None:
                dependency_version = dependency_version.text.strip()
            dependency_version = parsePropertyName(root, dependency_version)
            dependency_node.setName(dependency_project_name)
            dependency_node.setGroupId(dependency_group_id)
            dependency_node.setVersion(dependency_version)
            dependencies.append(dependency_node)
        for dependency in dependencies:
            # print(dependency)
            # 4
            dependency_version_node = query_dependency_version(dependency)
            if dependency_version_node is None:
                dependency_version_node = add_dependency_version(dependency)
            add_relation(version_node, 'dependency', dependency_version_node)
            dependency_node = query_dependency(dependency)
            if dependency_node is None:
                dependency_node = add_dependency(dependency)
            add_relation(dependency_version_node, 'belong to', dependency_node)
        # todo
        global project_software_dict
        project_software = Software()
        project_software.setSoftwareName(project.artifact_id)
        project_software.setVersion(project.version)
        software_version_node = query_software_version(project_software)
        if software_version_node is None:
            for project_name in project_software_dict[project.artifact_id]:
                if software_version_node is not None:
                    break
                project_software.setSoftwareName(project_name)
                software_version_node = query_software_version(project_software)
        if software_version_node is not None:
            add_relation(software_version_node, 'relevant to', version_node)
            add_relation(version_node, 'relevant to', software_version_node)
        print('Successfully finished.')
    except Exception as e:
        log_file = r'{0}/parse_log.txt'.format(LOG_DIR)
        log_info = 'Parse {0} error.'.format(fileName)
        write_log(log_file, log_info)
        print(e)


def parsePropertyName(root, property_name):
    if not (len(property_name) > 0 and property_name[0] is '$'):
        return property_name
    POM_NS = '{http://maven.apache.org/POM/4.0.0}'
    # 获取大括号中间的内容
    p = re.compile(r'[{](.*?)[}]', re.S)
    property_data = re.findall(p, property_name)
    if len(property_data) == 1:
        property_name = re.findall(p, property_name)[0]
        # data = root.find('%sproperties' % (POM_NS)).find('%s%s' % (POM_NS, property_name))
        properties = root.find('%sproperties' % (POM_NS))
        data = None
        if properties is None:
            if property_name.startswith('pom.'):
                try:
                    data = root.find('%s%s' % (POM_NS, property_name[4:]))
                except:
                    data = ''
        else:
            data = properties.find('%s%s' % (POM_NS, property_name))
        if data is not None:
            return data.text
        else:
            try:
                items = property_name.split('.')
                if items[0] == 'project':
                    data = root
                else:
                    data = root.find('%s%s' % (POM_NS, items[0]))
                for i in range(1, len(items)):
                    data = data.find('%s%s' % (POM_NS, items[i]))
                return data.text
            except:
                return ''
    else:
        result = ''
        for property_name in property_data:
            data = root.find('%sproperties' % (POM_NS)).find('%s%s' % (POM_NS, property_name))
            result = result + data.text
        return result


def run_parse():
    softwares = ['activemq', 'ambari', 'camel', 'cloudstack', 'cxf', 'geronimo', 'wicket', 'nifi']
    softwares = ['cxf']
    os.chdir(DEPENDENCY_DIR)
    for software in os.listdir(DEPENDENCY_DIR):
        if os.path.isdir(software):
            print(software)
            for file in os.listdir(software):
                file_path = r'{0}/{1}/{2}'.format(DEPENDENCY_DIR, software, file)
                parse_pom(software, file_path)
    # for software in softwares:
    #     for file in os.listdir(software):
    #         file_path = r'{0}/{1}/{2}'.format(DEPENDENCY_DIR, software, file)
    #         parse_pom(software, file_path)


# 找漏洞本体中的软件版本节点和项目依赖本体中的项目版本节点是否一致
def find_software_project():
    # nodes = query_all_project_version()
    # for node in nodes:
    #     item = list(node.values())
    #     project_name = item[1]
    #     version = item[2]
    #     file_path = r'{0}/project-version-info.txt'.format(DEPENDENCY_DIR)
    #     file = open(file_path, 'a')
    #     file.write(project_name + '\t' + version + '\n')
    file_path = r'{0}/project-version-info.txt'.format(DEPENDENCY_DIR)
    file = open(file_path, 'r')
    software_names = []
    for item in file.readlines():
        item_splits = item.split()
        if len(item_splits) <= 1:
            continue
        project_name = item_splits[0]
        if project_name in software_names:
            continue
        version = ''
        if len(item_splits) > 1:
            version = item_splits[1]
        # project_node = query_version_to_project(project_name)
        # print(project_name + '\t' + version + '\t' + str(project_node[0]['n']['name']))
        # print(project_name, version)
        project = Software()
        project.setSoftwareName(project_name)
        project.setVersion(version)
        software_version_node = query_software_version(project)
        if software_version_node is None:
            # print(project_name, version, software_version_node)
            software_names.append(project_name)
    for name in software_names:
        print(name)


# 查找漏洞本体的软件名和项目本体的项目名，进行命名对齐
def name_align():
    file_path = r'{0}/{1}'.format(DEPENDENCY_DIR, '命名对齐.txt')
    file = open(file_path, 'r')
    for item in file.readlines():
        project_name = item.strip()
        if '.' in project_name:
            print(project_name)
            continue
        version_nodes = fuzzy_query_software_version(project_name)
        if version_nodes is not None and len(version_nodes) > 0:
            print(project_name, end='')
            for version_node in version_nodes:
                print('\t' + version_node['n.software_name'], end='')
            print()
        else:
            project_name_temp = project_name
            if '-' in project_name_temp:
                project_name_temp = project_name_temp.replace('-', '_')
            if '_parent' in project_name_temp:
                project_name_temp = project_name_temp.replace('_parent', '')
            if '_project' in project_name_temp:
                project_name_temp = project_name_temp.replace('_project', '')
            version_nodes = fuzzy_query_software_version(project_name_temp)
            if version_nodes is not None and len(version_nodes) > 0:
                print(project_name, end='')
                for version_node in version_nodes:
                    print('\t' + version_node['n.software_name'], end='')
                print()
            else:
                print(project_name)


def test():
    graph = Graph('http://localhost:7474/', auth=('neo4j', '123456'))
    project_node = graph.nodes.match('Project').where("_.name='{0}'".format("Netty")).first()
    print(project_node)
    project_node['haha'] = 'haha'
    print(project_node)
    graph.push(project_node)


if __name__ == '__main__':
    # testParse(r'C:\Users\37537\Desktop\pom1.xml')
    # parsePom(r'C:\Users\37537\Desktop\pom.xml')
    # run()
    # getProjectName()
    # get_parent()
    # parse_pom('bookkeeper', r'D:\学习\研究生\毕业设计\data\dependencies\bookkeeper\release-4.3.0.xml')
    run_parse()
    # find_software_project()
    # name_align()

