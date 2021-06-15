# JVulDS
A system for using deep learning to detect vulnerabilities. 
### Introduction
For this system, firstly, we generate pdg of Java program including vulnerability focuses. In this step, we store the pdg nodes in the Neo4j database. If this node is related to vulnerability, we set the attribute type of the node to 1 or 2, or 3. Secondly, we generate program slice according to PDG. Thirdly, we transform program slice to vector by word2vec. Finally, we use the vector as the input of the deep learning to train dataset and predict test dataset.
### Description

* **DeepLearningFiles** includes all python files, models etc., to predict vulnerabilities by using deep neural network.
* **PDG** is used to generate pdg of java programs.
* **StaticService** integrated all steps to detect vulnerabilitis.

### Usage 
JVulDS is used for Linux or Mac os.

1. Install [Neo4j database](https://neo4j.com/download/) and open Neo4j database
```
$ cd neo4j/bin
$ ./neo4j console
```
2. Run PDG framework

* modify Configuration (as shown PDG/README.md)
```
$ cd JVulDS/PDG
$ mvn clean package
$ cd target
$ java -jar demo-0.0.1-SNAPSHOT.jar
```
3. Run StaticService

* Main class: com.snail.dldetectvul.run.VulDeePackerStaticService
* modify Config class (as shown StaticService/README.md)

```
$ cd StaticService
$ mvn clean package
$ cd target
$ java -jar demo-0.0.1-SNAPSHOT.jar -d projectPath
```
