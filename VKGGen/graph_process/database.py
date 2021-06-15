from py2neo import Graph, Node, Relationship, NodeMatch, RelationshipMatch, Subgraph

from common.models import Vulnerability

graph = Graph('http://localhost:7474/', auth=('neo4j', '123456'))
# graph = Graph('http://119.3.162.189:7474/', auth=('neo4j', '123456'))


def add_vulnerability(vuln):
    node = Node('Vulnerability', cve_id=vuln.cve_id, description=vuln.description, published_time=vuln.published_time,
                author=vuln.author, link=vuln.link)
    graph.create(node)
    return node


def add_vuln_type(vuln_type):
    node = Node('VulnType', cwe_id=vuln_type.cwe_id, description=vuln_type.description)
    graph.create(node)
    return node


def add_cvss(cvss):
    node = Node('CVSS', base_score=cvss.base_score, vector=cvss.vector)
    graph.create(node)
    return node


def add_software_version(software):
    node = Node('SoftwareVersion', software_name=software.software_name, version=software.version)
    graph.create(node)
    return node


def add_software(software):
    node = Node('Software', software_name=software.software_name, vendor=software.vendor)
    graph.create(node)
    return node


def add_vendor(vendor_name):
    node = Node('SoftwareVendor', vendor_name=vendor_name, url='')
    graph.create(node)
    return node


def add_exploit(url, description, code_file):
    node = Node('Exploit', url=url, description=description, code_file=code_file)
    graph.create(node)
    return node


def add_diff(diff):
    node = Node('VulnPatch', diff_url=diff.url, cve_id=diff.cve_id, software=diff.software, diff_file=diff.diff_file, language=diff.language)
    graph.create(node)
    return node


# 添加项目结点到图谱（dependency部分）
def add_project(project):
    node = Node('Project', name=project.project_name, artifact_id=project.artifact_id,
                description=project.description, url=project.url)
    graph.create(node)
    return node


def add_project_version(project):
    node = Node('ProjectVersion', project_name=project.artifact_id, version=project.version,
                group_id=project.group_id)
    graph.create(node)
    return node


def add_parent(parent):
    node = Node('Parent', name=parent.project_name, group_id=parent.group_id, description=parent.description)
    graph.create(node)
    return node


def add_dependency(dependency):
    node = Node('Dependency', project_name=dependency.project_name)
    graph.create(node)
    return node


def add_dependency_version(dependency):
    node = Node('DependencyVersion', project_name=dependency.project_name,
                project_version=dependency.version, group_id=dependency.group_id)
    graph.create(node)
    return node


def add_rule(rule):
    node = Node('VulnRule', cwe_id=rule.cwe_id, description=rule.description, rule_file=rule.rule_file)
    graph.create(node)
    return node


def add_relation(node1, relation, node2):
    relation_node = Relationship(node1, relation, node2)
    graph.create(relation_node)


def set_cwe_description(cwe_id, description):
    cypher = 'match (n:VulnType{cwe_id:"' + cwe_id + '"}) set n.description = "' + description + '"'
    # print(cypher)
    graph.run(cypher)


def query_vulnerability(cve_id):
    cypher = "match(a:Vulnerability{cve_id:'" + cve_id + "'}) return a"
    return graph.run(cypher).data()


def query_vuln_type(cwe_id):
    cypher = "match(a:VulnType{cwe_id:'" + cwe_id + "'}) return a"
    return graph.run(cypher).data()


def query_cwe_description_null():
    nodes = graph.nodes.match('VulnType').where('_.description=""')
    return list(nodes)


def query_cvss(cvss):
    # 注意这里base_score=后面不能加引号
    node = graph.nodes.match('CVSS').where("_.base_score={0} and _.vector='{1}'".format(
        str(cvss.base_score), str(cvss.vector))).first()
    return node


def query_software_version(software):
    node = graph.nodes.match('SoftwareVersion').where('_.software_name="{0}" and _.version="{1}"'.format(
        software.software_name, str(software.version))).first()
    return node


def fuzzy_query_software_version(keyword):
    cypher = "match (n:SoftwareVersion) where n.software_name=~'.*" + keyword + \
             ".*' return n.software_name,count(n.software_name)"
    return graph.run(cypher).data()


# 根据CVE号和软件名查找软件版本节点
def query_software_version_by_cs(cve_id, software_name):
    cypher = 'match (:Vulnerability{cve_id:"' + cve_id + '"})-[]-(n:SoftwareVersion{software_name:"' \
             + software_name + '"}) return n'
    return graph.run(cypher).data()


# 根据软件名查询该软件的cve总数（模糊查询）
def query_software_cve_num(software_name):
    cypher = 'match(n: Vulnerability) -[]->(m) where m.software_name=~".*' + software_name + \
             '.*" return count(n.cve_id)'
    return graph.run(cypher).data()

def query_software(software):
    node = graph.nodes.match('Software').where('_.software_name="{0}" and _.vendor="{1}"'.format(
        software.software_name, software.vendor)).first()
    return node


def query_vendor(vendor_name):
    node = graph.nodes.match('SoftwareVendor').where('_.vendor_name="{0}"'.format(vendor_name)).first()
    return node


def query_project(project):
    node = graph.nodes.match('Project').where("_.name='{0}' and _.artifact_id='{1}'"
                                              .format(project.project_name, project.artifact_id)).first()
    return node


def query_project_version(project):
    node = graph.nodes.match('ProjectVersion').where(
        "_.project_name='{0}' and _.version='{1}'".format(project.artifact_id, project.version)).first()
    return node


def query_all_project_version():
    nodes = graph.nodes.match('ProjectVersion')
    return nodes


# 查找项目版本节点对应的项目节点
def query_version_to_project(project_name):
    cypher = "match (n:Project)-[]->(m:ProjectVersion{project_name:'" + project_name + "'}) return n"
    return graph.run(cypher).data()


def query_parent(parent):
    node = graph.nodes.match('Parent').where("_.name='{0}' and _.group_id='{1}'"
                                             .format(parent.project_name, parent.group_id)).first()
    return node


def query_dependency(dependency):
    node = graph.nodes.match('Dependency').where("_.project_name='{0}'".format(dependency.project_name)).first()
    return node


def query_dependency_version(dependency):
    node = graph.nodes.match('DependencyVersion').where(
        "_.project_name='{0}' and _.project_version='{1}'".format(dependency.project_name, dependency.version)).first()
    return node


def test():
    graph = Graph('http://localhost:7474/', auth=('neo4j', '123456'))

    cypher = 'match(a:Location) return a.city,a.province'
    # nodes = graph.nodes.match("Location").first()
    # 查询结点
    # city = "Shenzhen"
    # cypher = "match(a:Location{city:'" + city + "'}) return a.city, a.province"
    # nodes = graph.run(cypher).data()
    # print(len(nodes))
    # for node in nodes:
    #     try:
    #         print(node['a.province'])
    #     except:
    #         continue

    # 创建结点
    vuln = Vulnerability()
    vuln.setCveId("CVE-TEST3")
    vuln.setDescription("Just a test3.")
    vuln.setPublishedTime('2000-01-01 15:37')
    node = Node('Vulnerability', cve_id=vuln.cve_id, description=vuln.description, published_time=vuln.published_time,
                author=vuln.author, link=vuln.link)
    graph.create(node)
    print(node)

    # 创建结点
    # cypher = "create (a:Person{name:'Test2'}) return a"
    # graph.run(cypher)

    # 删除节点
    # cypher = "match(a:Person{name:'Test'}) delete a"
    # graph.run(cypher)

    # locations = [['Wuhan', 'Hubei'], ['Shenzhen', 'Guangdong'], ['Huanggang', 'Hubei']]
    # for location in locations:
    #     cypher = "match(a:Location{city:'" + location[0] + "'}) return a.city,a.province"
    #     result = graph.run(cypher).data()
    #     if len(result) != 0:
    #         continue
    #     node = Node('Location', city=location[0], province=location[1])
    #     graph.create(node)

    # cve_id = 'CVE-2012-6031'
    # cypher = "match(a:Vulnerability{cve_id:'" + cve_id + "'}) return a.city,a.province"
    # result = graph.run(cypher).data()
    # print(len(result))


if __name__ == '__main__':
    # test()
    # node1 = query_vulnerability('CVE-TEST2')
    # print(node1)
    # node2 = query_vulnerability('CVE-TEST3')
    # print(node2)
    # rel1 = Relationship(node1[0]['a'], "equals", node2[0]['a'])
    # graph.create(rel1)
    # nodes = query_cwe_description_null()
    # print(nodes)
    nodes = query_software_version_by_cs('CVE-2019-0192', 'solr')
    for node in nodes:
        print(node['n'])
