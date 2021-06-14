package com.platform.demo.service;

import com.platform.demo.Config;
import com.platform.demo.MainTest;
import com.propertygraph.pdg.node.*;
import com.propertygraph.pe.*;

import org.eclipse.jdt.core.dom.CompilationUnit;
import org.springframework.stereotype.Service;
import com.propertygraph.ast.ASTVisitor;
import com.propertygraph.cfg.node.CFGNodeFactory;
import com.propertygraph.pdg.PDG;
import com.propertygraph.pdg.edge.PDGControlDependenceEdge;
import com.propertygraph.pdg.edge.PDGDataDependenceEdge;
import com.propertygraph.pdg.edge.PDGEdge;
import com.propertygraph.pdg.edge.PDGExecutionDependenceEdge;

import javax.annotation.Resource;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.*;

@Service
public class PdgService {
   public static long id;


    private void writePDG(final PDG pdg,
                          final int createdGraphNumber,
                          final BufferedWriter writer) throws IOException {
        final MethodInfo method = pdg.unit;

        writer.write("subgraph cluster");
        writer.write(Integer.toString(createdGraphNumber));
        writer.write(" {");
        writer.newLine();

        writer.write("label = \"");
        writer.write(Common.getMethodSignature(method));
        writer.write("\";");
        writer.newLine();

        final Map<PDGNode<?>, Integer> nodeLabels = new HashMap<PDGNode<?>, Integer>();
        //final SortedSet<PDGNode<?>> nodes = pdg.getAllNodes();
        for (final PDGNode<?> node : pdg.getAllNodes()) {
            nodeLabels.put(node, nodeLabels.size());
        }

        for (final Map.Entry<PDGNode<?>, Integer> entry : nodeLabels.entrySet()) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(entry.getValue()));
            writer.write(" [style = filled, label = \"");
            writer.write(entry.getKey().getText().replace("\"", "\\\"")
                    .replace("\\\\\"", "\\\\\\\""));
            writer.write("\"");

            final PDGNode<?> node = entry.getKey();
            if (node instanceof PDGMethodEnterNode) {
                writer.write(", fillcolor = aquamarine");
            } else if (pdg.getExitNodes().contains(node)) {
                writer.write(", fillcolor = deeppink");
            } else if (node instanceof PDGParameterNode) {
                writer.write(", fillcolor = tomato");
            } else {
                writer.write(", fillcolor = white");
            }

            if (node instanceof PDGControlNode) {
                writer.write(", shape = diamond");
            } else if (node instanceof PDGParameterNode) {
                writer.write(", shape = box");
            } else {
                writer.write(", shape = ellipse");
            }

            writer.write("];");
            writer.newLine();
        }

        for (final PDGEdge edge : pdg.getAllEdges()) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.fromNode)));
            writer.write(" -> ");
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.toNode)));
            if (edge instanceof PDGDataDependenceEdge) {
                writer.write(" [style = solid, label=\""
                        + edge.getDependenceString() + "\"]");
            } else if (edge instanceof PDGControlDependenceEdge) {
                writer.write(" [style = dotted, label=\""
                        + edge.getDependenceString() + "\"]");
            } else if (edge instanceof PDGExecutionDependenceEdge) {
                writer.write(" [style = bold, label=\""
                        + edge.getDependenceString() + "\"]");
            }
            writer.write(";");
            writer.newLine();
        }

        writer.write("}");
        writer.newLine();
    }

    public String toJson(String path, HttpServletResponse response) {
        //path = "/Users/ke/Documents/snail/graduate/platform/serverTest/GraphTest/A.java";
        final File f= new File(path);
        if (!f.exists()){
            return "没有上传文件";
        }

        final File file = MainTest.getFiles(f).get(0);

        final List<MethodInfo> methods = new ArrayList<MethodInfo>();
        final CompilationUnit unit = ASTVisitor.createAST(file);
        final List<MethodInfo> m = new ArrayList<MethodInfo>();
        final ASTVisitor visitor = new ASTVisitor(
                file.getAbsolutePath(), unit, methods);
        unit.accept(visitor);
        methods.addAll(m);

        StringBuilder nodes = new StringBuilder();
        StringBuilder relationship = new StringBuilder();
        nodes.append("\"nodes\": [" + "\n");
        relationship.append("\"relationships\": [" + "\n");
        id = 0;//TODO

        //文件节点
        GenerateJson.toFile(file.getName(),nodes,id);
        long fileID = id;
        id++;
        boolean flag = true;
        for(MethodInfo method :methods){
            final PDG pdg = new PDG(method, new PDGNodeFactory(),
                    new CFGNodeFactory(), true, true, true);
            pdg.build();

            //method节点
            GenerateJson.toMethod(method, nodes, id);
            long methodID = id;
            id++;

            //statement节点
            Map<PDGNode<?>, Long> map = new HashMap<>();
            for (PDGNode pdgNode : pdg.getAllNodes()) {
                nodes.append(",");
                nodes.append("\n");
                GenerateJson.toStatement(pdgNode, nodes, id);
                map.put(pdgNode, id);
                id++;
            }

            //关系

            //文件和方法的关系
            if (flag) {
                GenerateJson.ISClassOf(fileID, methodID, relationship, id);
                flag = false;
            }
            else {
                relationship.append("," + "\n");
                GenerateJson.ISClassOf(fileID, methodID, relationship, id);
            }
            id++;
            //边与边之间的关系
            for (final PDGEdge edge : pdg.getAllEdges()) {
                if (edge.fromNode instanceof PDGMethodEnterNode){
                    relationship.append(",");
                    relationship.append("\n");
                    GenerateJson.link(methodID, map.get(edge.fromNode), relationship, id, "enter", "ENTER" );
                    id++;
                }
                if (edge instanceof PDGControlDependenceEdge){
                    relationship.append(",");
                    relationship.append("\n");
                    GenerateJson.link(map.get(edge.fromNode), map.get(edge.toNode), relationship, id, edge.getDependenceString(), "CD");
                }
                else if (edge instanceof PDGDataDependenceEdge){
                    relationship.append(",");
                    relationship.append("\n");
                    GenerateJson.link(map.get(edge.fromNode), map.get(edge.toNode), relationship, id, edge.getDependenceString(), "DD");
                }
//                else if (edge instanceof PDGExecutionDependenceEdge){
//                    relationship.append(",");
//                    relationship.append("\n");
//                    GenerateJson.link(map.get(edge.fromNode), map.get(edge.toNode), relationship, id, edge.getDependenceString(), "ED");
//                }
                id++;
            }

        }
        nodes.append("\n" + "]," + "\n");
        relationship.append("\n" + "]" + "\n");

        StringBuilder resultJson = new StringBuilder();
        resultJson.append("{");
        resultJson.append("\"results\": [{" + '\n');
        resultJson.append("\"data\": [{" + '\n');
        resultJson.append("\"graph\": {" + '\n');
        //if (id < Config.maxNums) {
            resultJson.append(nodes);
            resultJson.append(relationship);
        //}
        resultJson.append("}" + "\n");
        resultJson.append("}]" + "\n");
        resultJson.append("}]" + "\n");
        resultJson.append("}");


        try {
            ServletOutputStream out=response.getOutputStream();
            out.write(resultJson.toString().getBytes());
            out.close();
        }catch (Exception e)
        {
            e.printStackTrace();
        }
        return resultJson.toString();
    }

}
