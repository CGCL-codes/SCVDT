package com.hust.kg.service;

import com.hust.kg.entity.PathConfig;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Record;
import org.neo4j.driver.Result;
import org.neo4j.driver.Value;
import org.neo4j.driver.internal.value.NodeValue;
import org.neo4j.driver.internal.value.PathValue;
import org.neo4j.driver.internal.value.RelationshipValue;
import org.neo4j.driver.types.Node;
import org.neo4j.driver.types.Path;
import org.neo4j.driver.types.Relationship;
import org.springframework.data.neo4j.core.DatabaseSelectionProvider;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import javax.swing.*;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

/**
 * @Author wk
 * @Date 2021/03/28 22:31
 * @Description:
 */
@Service
public class CypherService {
    private final Neo4jClient neo4jClient;

    private final Driver driver;

    private final DatabaseSelectionProvider databaseSelectionProvider;

    public CypherService(Neo4jClient neo4jClient, Driver driver, DatabaseSelectionProvider databaseSelectionProvider) {
        this.neo4jClient = neo4jClient;
        this.driver = driver;
        this.databaseSelectionProvider = databaseSelectionProvider;
    }

    public String executeCypher(String cypher){
        System.out.println(cypher);
        Result result = this.driver.session().run(cypher);
        StringBuffer nodes = new StringBuffer();
        StringBuffer relations = new StringBuffer();
        nodes.append("\"nodes\":[");
        relations.append("\"relationships\":[");
        Map<Long, Boolean> map = new HashMap<>();
        int nodeNum = 0;
        int relationNum = 0;
        while(result.hasNext()) {
            Record record = result.next();
            List<Value> list = record.values();
            for (Value v : list) {
//                System.out.println(v);
//                System.out.println(v.getClass());
                if (PathValue.class.equals(v.getClass())) {
                    Path p = v.asPath();
                    for(Node node:p.nodes()){
                        if(map.containsKey(node.id())){
                            continue;
                        }
                        map.put(node.id(), true);
                        StringBuffer nodeStr = new StringBuffer();
                        nodeStr.append("{");
                        nodeStr.append("\"id\":" + node.id() + ",");
                        nodeStr.append("\"labels\":[");
                        int num = 0;
                        for(String label:node.labels()){
                            if(num == 0){
                                nodeStr.append("\"" + label + "\"");
                            }
                            else{
                                nodeStr.append(",\"" + label + "\"");
                            }
                            num++;
                        }
                        nodeStr.append("],");
                        nodeStr.append("\"properties\":{");
                        num = 0;
                        for(String key:node.keys())
                        {
                            if(num == node.size()-1) {
                                nodeStr.append("\""+key+"\":"+node.get(key));
                            }else{
                                nodeStr.append("\""+key+"\":"+node.get(key)+",");
                            }
                            num ++ ;
                        }
                        nodeStr.append("}}");
                        if(nodeNum == 0){
                            nodes.append(nodeStr);
                        }else{
                            nodes.append("," + nodeStr);
                        }
                        nodeNum++;
//                        nodes.append("}},");
                    }
//                    nodes=new StringBuffer(nodes.toString().substring(0,nodes.toString().length()-1));
                    for(Relationship relationship:p.relationships())
                    {
                        if(map.containsKey(relationship.id())){
                            continue;
                        }
                        map.put(relationship.id(), true);
                        StringBuffer relationStr = new StringBuffer();
                        relationStr.append("{");
                        relationStr.append("\"id\":" + relationship.id() + ",");
                        relationStr.append("\"type\":\"" + relationship.type() + "\",");
                        relationStr.append("\"startNode\":"+relationship.startNodeId()+","+"\"endNode\":"+relationship.endNodeId());
                        int num = 0;
                        for(String key:relationship.keys()){
                            if(num == 0){
                                relationStr.append(",\"properties\":{");
                            }
                            if(num == relationship.size()-1){
                                relationStr.append("\"" + key + "\":" + relationship.get(key) + "}");
                            }
                            else{
                                relationStr.append("\"" + key + "\":" + relationship.get(key) + ",");
                            }
                            num++;
                        }
                        relationStr.append("}");
                        if(relationNum == 0){
                            relations.append(relationStr);
                        }else {
                            relations.append("," + relationStr);
                        }
                        relationNum++;
//                        relations.append("},");
                    }
//                    relations=new StringBuffer(relations.toString().substring(0,relations.toString().length()-1));
                } else if (NodeValue.class.equals(v.getClass())) {
                    Node node = v.asNode();
                    if(map.containsKey(node.id())){
                        continue;
                    }
                    map.put(node.id(), true);
                    StringBuffer nodeStr = new StringBuffer();
                    nodeStr.append("{");
                    nodeStr.append("\"id\":" + node.id() + ",");
                    nodeStr.append("\"labels\":[");
                    int num = 0;
                    for(String label:node.labels()){
                        if(num == 0){
                            nodeStr.append("\"" + label + "\"");
                        }
                        else{
                            nodeStr.append(",\"" + label + "\"");
                        }
                        num++;
                    }
                    nodeStr.append("],");
                    nodeStr.append("\"properties\":{");
                    num = 0;
                    for(String key:node.keys())
                    {
                        if(num == node.size()-1) {
                            nodeStr.append("\""+key+"\":"+node.get(key));
                        }else{
                            nodeStr.append("\""+key+"\":"+node.get(key)+",");
                        }
                        num ++ ;
                    }
                    nodeStr.append("}}");
                    if(nodeNum == 0){
                        nodes.append(nodeStr);
                    }else{
                        nodes.append("," + nodeStr);
                    }
                    nodeNum++;
                }else if(RelationshipValue.class.equals(v.getClass())){
                    Relationship relationship = v.asRelationship();
                    if(map.containsKey(relationship.id())){
                        continue;
                    }
                    map.put(relationship.id(), true);
                    StringBuffer relationStr = new StringBuffer();
                    relationStr.append("{");
                    relationStr.append("\"id\":" + relationship.id() + ",");
                    relationStr.append("\"type\":\"" + relationship.type() + "\",");
                    relationStr.append("\"startNode\":"+relationship.startNodeId()+","+"\"endNode\":"+relationship.endNodeId());
                    int num = 0;
                    for(String key:relationship.keys()){
                        if(num == 0){
                            relationStr.append(",\"properties\":{");
                        }
                        if(num == relationship.size()-1){
                            relationStr.append("\"" + key + "\":" + relationship.get(key) + "}");
                        }
                        else{
                            relationStr.append("\"" + key + "\":" + relationship.get(key) + ",");
                        }
                        num++;
                    }
                    relationStr.append("}");
                    if(relationNum == 0){
                        relations.append(relationStr);
                    }else {
                        relations.append("," + relationStr);
                    }
                    relationNum++;
//                    relationStr
//                    relations.append("},");
                }else{
                    // TODO: 2021/3/29 0:42 
                }
            }
        }
//        nodes=new StringBuffer(nodes.toString().substring(0,nodes.toString().length()-1));
//        relations=new StringBuffer(relations.toString().substring(0,relations.toString().length()-1));

        nodes.append("]");
        relations.append("]");
        String jsonStr = "{\"results\":[{\"data\":[{\"graph\":{" + nodes.toString() + "," + relations.toString() + "}}]}]}";
        try {
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(PathConfig.downloadPath + "/cypher-data.json"));
            bufferedWriter.write(jsonStr);
            bufferedWriter.newLine();
            bufferedWriter.close();
        }catch (IOException e) {
            //TODO
        }
        return jsonStr;
    }
}
