package com.propertygraph.graphToDot;

import com.platform.astdemo.generator.ASTGenerator;
import com.platform.astdemo.generator.ASTtoDOT;
import com.platform.astdemo.structure.MyMethodNode;
import com.platform.demo.Config;
import com.platform.demo.MainTest;

import java.io.*;
import java.util.List;

public class SaveAST {
    public static void save(File f){
        String outPaths = f.getParent() + File.separator + "AST";
        File out = new File(outPaths);
        if (out.exists()){
            MainTest.deleteFile(out.listFiles());
        }
        if (!out.exists()){
            out.mkdirs();
        }

        List<File> files = MainTest.getFiles(f);
        for (File file : files) {
            ASTGenerator astGenerator = new ASTGenerator(file);
            List<MyMethodNode> methodNodeList = astGenerator.getMethodNodeList();

            String outPath = outPaths + File.separator + file.getName().replace(".java", "_ast.dot");

            try {
                final BufferedWriter writer = new BufferedWriter(
                        new FileWriter(outPath));
                writer.write("digraph AST {");
                writer.newLine();

                int createNum = 0;
                for (MyMethodNode myMethodNode : methodNodeList) {
                    String dot = ASTtoDOT.ASTtoDotParser(myMethodNode, createNum);
                    createNum++;
                    writer.write(dot);
                }
                writer.write("}");
                writer.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
