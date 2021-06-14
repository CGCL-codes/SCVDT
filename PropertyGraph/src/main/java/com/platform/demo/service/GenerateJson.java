package com.platform.demo.service;

import com.platform.astdemo.structure.MyASTNode;
import org.eclipse.jdt.core.dom.ASTNode;
import com.propertygraph.cfg.node.CFGControlNode;
import com.propertygraph.cfg.node.CFGNode;
import com.propertygraph.pdg.node.PDGNode;
import com.propertygraph.pe.MethodInfo;

public class GenerateJson {
    public static void toFile(String path, StringBuilder nodes, long id){
        nodes.append("{" + "\n");
        nodes.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        nodes.append("\"labels\": " + "[\"File\"]," + "\n");
        nodes.append("\"properties\": {" + "\n" +
                "\"className\": " + "\"" + path + "\"" + "\n" +
                "}" + "\n");
        nodes.append("}");
        //return nodes;
    }

    public static void toMethod(MethodInfo methodInfo, StringBuilder nodes, long id){
        nodes.append("," + "\n");
        nodes.append("{" + "\n");
        nodes.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        nodes.append("\"labels\": " + "[\"Method\"]," + "\n");
        nodes.append("\"properties\": {" + "\n" +
                "\"code\": " + "\"" + methodInfo.name + "\"," + "\n" +
                "\"startLine\": " + "\"" + methodInfo.startLine + "\"," + "\n" +
                "\"endLine\": " + "\"" + methodInfo.endLine + "\"" + "\n" +
                "}" + "\n");
        nodes.append("}");
    }

    public static void toStatement(PDGNode pdgNode, StringBuilder nodes, long id){
        nodes.append("{" + "\n");
        nodes.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        nodes.append("\"labels\": " + "[\"Statement\"]," + "\n");
        nodes.append("\"properties\": {" + "\n" +
                "\"code\": " + "\"" + pdgNode.core.getText().replace("\"", "\\\"")
                .replace("\\\\\"", "\\\\\\\"") + "\"," + "\n" +
                "\"startLine\": " + "\"" + pdgNode.core.startLine + "\"," + "\n" +
                "\"endLine\": " + "\"" + pdgNode.core.endLine + "\"" + "\n" +
                "}" + "\n");
        nodes.append("}");
    }

    public static void ISClassOf(long parent, long child, StringBuilder relationship, long id){
        relationship.append("{" + "\n");
        relationship.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        relationship.append("\"type\": " + "\"is_class_of\"" + "," + "\n");
        relationship.append("\"startNode\": " + "\"" + String.valueOf(parent) + "\"" + "," + "\n");
        relationship.append("\"endNode\": " + "\"" + String.valueOf(child) + "\""  + "\n");
        relationship.append("}");
    }

    public static void link(long parent, long child, StringBuilder relationship, long id, String message, String res){

        relationship.append("{" + "\n");
        relationship.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        relationship.append("\"type\": " + "\"" + res + "\"" + "," + "\n");
        relationship.append("\"startNode\": " + "\"" + String.valueOf(parent) + "\"" + "," + "\n");
        relationship.append("\"endNode\": " + "\"" + String.valueOf(child) + "\"" + "," + "\n");
        relationship.append("\"properties\": {" + "\n" +
                "\"message\": " + "\"" + message + "\"" + "\n" +
                "}" + "\n");
        relationship.append("}");
    }

    public static void toStatement_cfg(CFGNode cfgNode, StringBuilder nodes, long id){
        String isControlNode = "false";
        if (cfgNode instanceof CFGControlNode){
            isControlNode = "true";
        }
        nodes.append("{" + "\n");
        nodes.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        nodes.append("\"labels\": " + "[\"Statement\"]," + "\n");
        nodes.append("\"properties\": {" + "\n" +
                "\"code\": " + "\"" + cfgNode.core.getText().replace("\"", "\\\"")
                .replace("\\\\\"", "\\\\\\\"") + "\"," + "\n" +
                "\"startLine\": " + "\"" + cfgNode.core.startLine + "\"," + "\n" +
                "\"endLine\": " + "\"" + cfgNode.core.endLine + "\"," + "\n" +
                "\"isCFGControlNode\": " + "\"" + isControlNode + "\"" + "\n" +
                "}" + "\n");
        nodes.append("}");
    }

    public static void toMethod_ast(String name, StringBuilder nodes, long id){
        nodes.append("," + "\n");
        nodes.append("{" + "\n");
        nodes.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        nodes.append("\"labels\": " + "[\"Method\"]," + "\n");
        nodes.append("\"properties\": {" + "\n" +
                "\"code\": " + "\"" + name + "\"" + "\n" +
                "}" + "\n");
        nodes.append("}");
    }

    public static void toStatement_ast(MyASTNode node, long id, StringBuilder nodes){
        nodes.append(",");
        nodes.append("\n");
        nodes.append("{" + "\n");
        nodes.append("\"id\": " + "\"" + String.valueOf(id) + "\"" + "," + "\n");
        nodes.append("\"labels\": " + "[\"Statement\"]," + "\n");
        nodes.append("\"properties\": {" + "\n" +
                "\"code\": " + "\"" + getText(node) + "\"," + "\n" +
                "\"startLine\": " + "\"" + String.valueOf(node.startLineNum) + "\"," + "\n" +
                "\"endLine\": " + "\"" + String.valueOf(node.endLineNum) + "\"," + "\n" +
                "\"category\": " + "\"" + getType(node) + "\"" + "\n" +
                "}" + "\n");
        nodes.append("}");
    }

    private static String getText(MyASTNode node){
        return node.astNode.toString().replace("\n", " ").replace("\"", "\\\"").replace("  ", " ");
    }

    private static String getType(MyASTNode node) {
        return ASTNode.nodeClassForType(node.astNode.getNodeType()).getName().replace("org.eclipse.jdt.core.dom.", "");
    }
}
