# PropertyGraph
A library to generate Abstract Syntax Tree, Control Flow Graph and Program Dependency Graph for Java programs.
## Environment
JDK version 8+.
## Generate PropertyGraph
```
Main class: com.propertygraph.graphToDot.Write
```

#### Usage
```
$ cd out/artifacts/PropertyGraph_jar
$ java -jar PropertyGraph.jar [-d <projectPath>] [-p] [-c] [-a]
-d projectPath  
-p: choose to generate PDG
-c: choose to generate CFG
-a: choose to generate AST
```
**Example**

`java -jar PropertyGraph.jar -d test/src -p -c -a`
