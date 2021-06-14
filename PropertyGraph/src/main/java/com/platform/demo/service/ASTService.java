package com.platform.demo.service;

import com.platform.astdemo.generator.ASTGenerator;
import com.platform.astdemo.structure.MyASTNode;
import com.platform.astdemo.structure.MyMethodNode;
import com.platform.demo.MainTest;
import org.springframework.stereotype.Service;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ASTService {
    public static long id;

    public String toJson(String path, HttpServletResponse response){
        //path = "/Users/ke/Documents/snail/graduate/platform/serverTest/GraphTest/A.java";

        final File f = new File(path);

        if (!f.exists()){
            return "没有上传文件";
        }

        final File file = MainTest.getFiles(f).get(0);

        StringBuilder nodes = new StringBuilder();
        StringBuilder relationships = new StringBuilder();
        nodes.append("\"nodes\": [" + "\n");
        relationships.append("\"relationships\": [" + "\n");
        id = 0;//TODO

        GenerateJson.toFile(file.getName(), nodes, id);
        long fileID = id;
        id++;

        boolean flag = true;

        ASTGenerator astGenerator = new ASTGenerator(file);
        List<MyMethodNode> methodNodeList = astGenerator.getMethodNodeList();
        for (MyMethodNode myMethodNode : methodNodeList){
            GenerateJson.toMethod_ast(myMethodNode.methodNode.getName().toString(), nodes, id);
            long methodID = id;
            id++;

            Map<Integer, Long> map = new HashMap<>();

            if (flag){
                GenerateJson.ISClassOf(fileID, methodID, relationships, id);
                id++;
                flag = false;
            }
            else {
                relationships.append("," + "\n");
                GenerateJson.ISClassOf(fileID, methodID, relationships, id);
                id++;
            }

            for (MyASTNode node : myMethodNode.nodeList){
                GenerateJson.toStatement_ast(node, id, nodes);

                if (map.size() == 0 || map == null) {
//                    //if (flag) {
//                        GenerateJson.link(methodID, id, relationships, id + 1, "", "");
//                        flag = false;
//                    }
//                    else {
                        relationships.append("," + "\n");
                        GenerateJson.link(methodID, id, relationships, id + 1, "", "");
                    //}
                    map.put(node.astNode.hashCode(), id);
                    id++;
                }
                else {
                    map.put(node.astNode.hashCode(), id);
                }
                id++;
            }

//            relationships.append("," + "\n");
//            GenerateJson.ISClassOf(fileID, methodID, relationships, id);

            for (int[] k : myMethodNode.mapping){
                int parent = k[0];
                int child = k[1];
                relationships.append(",");
                relationships.append("\n");
                GenerateJson.link(map.get(parent),map.get(child),relationships,id, "", "");
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
