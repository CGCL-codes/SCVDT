# VKGServe
VKGServe is a background program that performs vulnerability knowledge graph operations. It completes CARD operations on vulnerability knowledge through the form of the Restful API interface.

## Introduction
We use the [Neo4j](https://neo4j.com/) graph database as the storage of the vulnerability knowledge graph. The constructed vulnerability knowledge graph contains two structures: the vulnerability relation network and the dependency relation network.

* **Vulnerability relation network:** Vulnerability network contains basic information of vulnerabilities, software information affected by vulnerabilities, patch code information contained in vulnerabilities, etc., through the knowledge graph to associate different dimensions of vulnerability information to facilitate the management, analysis and research of vulnerabilities.
* **Dependency relation network:** The phenomenon of dependent calls in Java software projects provides ideas for analyzing and detecting vulnerabilities. Based on the dependent information collected by the vulnerability data collection module, we constructs the dependent entities, which vividly characterizes the calling relationship of the software project to different dependent libraries.

## Usage

### Environment
<!-- * JDK 1.8
* neo4j-community 3.5.17
* maven 3 -->
|  Tools   | Version  |
|  :----  | :----  |
| JDK  | >=1.8 |
| neo4j  | >=3.5 |
| maven | >=3.1 |

### Setup
* Unzip the vulKG-database.zip and place it in the data directory of Neo4j
```shell
$ cd database
$ unzip vulKG-database.zip
$ mv graph.db ${NEO_4J}/data/databases
```
* Configure neo4j in application.properties
```shell
server.port=${PORT:8123}
spring.neo4j.uri=bolt://localhost:7687
spring.neo4j.authentication.username=your_database
spring.neo4j.authentication.password=your_password
```
* Run KgApplication.java to start vulnerability knowledge graph serve

### Running Examples
* To test the API interface of query vulnerability
```html
http://localhost:8123/vulnerability?cve_id=CVE-2020-0001
```