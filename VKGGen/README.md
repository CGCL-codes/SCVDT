# VKGGen
VKGGen is a tool to process data and generate vulnerability knowledge graph.

## Introduction
We construct a vulnerability knowledge graph based on multi-source vulnerability data. The structure of the designed vulnerability knowledge graph is shown in the figure below. The knowledge graph contains two major structures: vulnerability ontology and dependeny ontology. Each ontology contains multiple entities. The entities form a network of vulnerability relationships that contain a lot of information through different relationships.

![image](https://github.com/hustwkk/VKGGen/blob/main/images/ontology-structure.png)

### Entities of Vulnerability ontology
The following tables show the attribute definitions of various vulnerability entities in the vulnerability knowledge graph.
* **Vulnerability**

  |    property    | description |
  | ---------- | --- |
  | cve_id |  vulnerability identifier |
  | description       |  vulnerability description information |
  | published_time     |  which time published |
  | author       |  author of the vulnerability |
  | link       |  link of the vulnerability |

* **VulnType**

  |    property    | description |
  | ---------- | --- |
  | cwe_id |  vulnerability type identifier |
  | description       |  vulnType description information |

* **CVSS**

  |    property    | description |
  | ---------- | --- |
  | base_score |  vulnerability score |
  | vector       |  vulnType vector |

* **Exploit**

  |    property    | description |
  | ---------- | --- |
  | description |  exploit description information |
  | url       |  exploit link |
  | code_file       |  POC file name |

* **VulnPatch**

  |    property    | description |
  | ---------- | --- |
  | diff_url |  vulnerability patch link |
  | cve_id       |  vulnerability identifier |
  | software       |  software where the patch is located |
  | diff_file       |  patch file name |

* **VulnRule**

  |    property    | description |
  | ---------- | --- |
  | cwe_id |  vulnerability type |
  | description       |  rule description information |
  | rule_file       |  rule file name |

* **SoftwareVersion**

  |    property    | description |
  | ---------- | --- |
  | software_name |  software name |
  | version       |  software version |

* **Software**

  |    property    | description |
  | ---------- | --- |
  | software_name |  software name |
  | vendor       |  software vendor |

* **SoftwareVendor**

  |    property    | description |
  | ---------- | --- |
  | vendor_name |  vendor name |
  | url       |  vendor link |

### Entities of Dependency ontology
The following tables show the attribute definitions of various dependency entities in the vulnerability knowledge graph.
* **Project**

  |    property    | description |
  | ---------- | --- |
  | name |  project name |
  | artifact_id       |  project unique identifier |
  | description     |  project description information |
  | url       |  project link |

* **ProjectVersion**

  |    property    | description |
  | ---------- | --- |
  | project_name |  project name |
  | version       |  project version |
  | group_id       |  project group ID |

* **Parent**

  |    property    | description |
  | ---------- | --- |
  | name | parent project name |
  | group_id       |  project group ID |
  | description       |  project description information |

* **Dependency**

  |    property    | description |
  | ---------- | --- |
  | project_name |  project name |

* **DependencyVersion**

  |    property    | description |
  | ---------- | --- |
  | project_name | dependent project name |
  | project_version       |  dependent project version |
  | group_id       |  project description information |

## Usage
### Environment
|  Tools   | Version  |
|  :----  | :----  |
| Python  | >=3.8 |
| neo4j  | >=3.5 |
| MySQL  | >=8.0 |

### Install
```shell
$ pip3 install graphviz==2.38
$ pip3 install py2neo==4.3.0
$ pip3 install pymysql==0.9.3
$ pip3 install urllib
$ pip3 install Beautifulsoup4
$ pip3 install pandas
```

### Setup
* Configure path in common/config.py
* Create table **exploit_graph** in the mysql environment
```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `exploit_graph`;
CREATE TABLE `exploit_graph`  (
  `ID` int(0) NOT NULL AUTO_INCREMENT,
  `CVE_ID` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `EDB_ID` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `URL` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `Description` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `Code_File` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  PRIMARY KEY (`ID`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 9 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;
SET FOREIGN_KEY_CHECKS = 1;
```
* Configure mysql in update.py and exploit.py of data_process directory
```python
connection = pymysql.connect(host='127.0.0.1', user='your_username', passwd='your_password', port=3306, db='your_database', charset='utf8')
```
* Configure neo4j in graph_process/database.py
```python
graph = Graph('http://localhost:7474/', auth=('your_database', 'your_password'))
```
* Run the python file in data_process directory for different operations

1. vulnerability.py: parse the relevant data of the [NVD](https://nvd.nist.gov/) and create vulnerability-related nodes in the knowledge graph

2. update.py: automatically obtain the latest vulnerability data and update the vulnerability knowledge graph
3. diff.py: add the collected vulnerability patch files to the knowledge graph
4. exploit.py: automatically crawl the exploit files and add the exploit nodes to vulnerability knowledge graph
5. software.py: download the dependency files(pom.xml) of java softwares
6. dependency.py: parse the pom.xml file, and import the software dependency call information into the vulnerability knowledge graph to construct the corresponding node

### Running Examples
* To initialize vulnerability knowledge graph with vulnerability information
```shell
cd data_process
python3 vulnerability.py
```

* To update the vulnerability knowledge graph
```shell
cd data_process
python3 update.py
```