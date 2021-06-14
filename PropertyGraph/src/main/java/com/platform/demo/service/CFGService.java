package com.platform.demo.service;

import com.platform.demo.MainTest;

import org.eclipse.jdt.core.dom.CompilationUnit;
import org.springframework.stereotype.Service;
import com.propertygraph.ast.ASTVisitor;
import com.propertygraph.cfg.CFG;
import com.propertygraph.cfg.edge.CFGEdge;

import com.propertygraph.cfg.node.CFGNode;
import com.propertygraph.cfg.node.CFGNodeFactory;
import com.propertygraph.pe.MethodInfo;
import com.propertygraph.pe.ProgramElementInfo;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.*;

@Service
public class CFGService {

    public static long id;

    public String toJsonCfg(String path, HttpServletResponse response) throws IOException{
        //path = "/Users/ke/Documents/snail/graduate/platform/serverTest/GraphTest/A.java";
        final File f = new File(path);
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

        id = 0;//TODO
        StringBuilder nodes = new StringBuilder();
        StringBuilder relationships = new StringBuilder();
        nodes.append("\"nodes\": [" + "\n");
        relationships.append("\"relationships\": [" + "\n");

        //文件节点
        GenerateJson.toFile(file.getName(), nodes, id);
        long fileID = id;
        id++;
        boolean flag = true;

        final CFGNodeFactory nodeFactory = new CFGNodeFactory();
        for (final MethodInfo method : methods){
            final CFG cfg = new CFG(method, nodeFactory);
            cfg.build();
            cfg.removeSwitchCases();
            cfg.removeJumpStatements();

            //method节点
            GenerateJson.toMethod(method, nodes, id);
            long methodID = id;
            id++;

            //statement node  TODO 可能是一样的节点？为什么会一样呢。。。
            final SortedMap<CFGNode<? extends ProgramElementInfo>, Long> map = new TreeMap<>();
            final CFGNode<? extends ProgramElementInfo> enterNode = cfg
                    .getEnterNode();

            final SortedSet<CFGEdge> edges = new TreeSet<CFGEdge>();
            for (final CFGNode<?> node : cfg.getAllNodes()) {
                edges.addAll(node.getBackwardEdges());
                edges.addAll(node.getForwardEdges());
            }

            for (final CFGNode<?> node : cfg.getAllNodes()){
                nodes.append(",");
                nodes.append("\n");
                GenerateJson.toStatement_cfg(node, nodes, id);
                map.put(node, id);
                id++;
            }

            //文件与方法之间的关系
            if (flag){
                GenerateJson.ISClassOf(fileID, methodID, relationships, id);
                flag = false;
            }
            else {
                relationships.append("," + "\n");
                GenerateJson.ISClassOf(fileID, methodID, relationships, id);
            }
            id++;


            for (final CFGEdge edge : edges) {
                if (edge.fromNode == enterNode){
                    relationships.append(",");
                    relationships.append("\n");
                    GenerateJson.link(methodID,map.get(edge.fromNode), relationships, id, "enter", "ENTER");
                    id++;
                }
                relationships.append(",");
                relationships.append("\n");
                if (map.get(edge.fromNode) == null){
                    System.out.println(edge.fromNode.core.getText());
                    continue;
                }
                if (map.get(edge.toNode) == null){
                    System.out.println(edge.toNode.core.getText());
                    continue;
                }
                GenerateJson.link(map.get(edge.fromNode), map.get(edge.toNode), relationships, id, edge.getDependenceString(), "C");
                id++;
            }

            // 边为空 但是节点不为空 边为空 只有一个节点
            if (edges.size() == 0 && map.size() == 1){
                relationships.append(",");
                relationships.append("\n");
                GenerateJson.link(methodID,map.get(cfg.getEnterNode()), relationships, id, "enter", "ENTER");
                id++;
            }
        }

        nodes.append("\n" + "]," + "\n");
        relationships.append("\n" + "]" + "\n");

        StringBuilder resultJson = new StringBuilder();
        resultJson.append("{");
        resultJson.append("\"results\": [{" + '\n');
        resultJson.append("\"data\": [{" + '\n');
        resultJson.append("\"graph\": {" + '\n');
        //if (id < Config.maxNums) {
            resultJson.append(nodes);
            resultJson.append(relationships);
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
