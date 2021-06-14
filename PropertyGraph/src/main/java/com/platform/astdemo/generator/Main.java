package com.platform.astdemo.generator;

import java.io.File;
import java.io.IOException;
import java.util.List;

import com.platform.astdemo.util.FileUtil;
import com.platform.astdemo.generator.*;
import com.platform.astdemo.structure.MyMethodNode;

public class Main {
	
	/**
	 * given the path of a java program which you want to parse and the output directory
	 * @param args
	 * @throws IOException
	 */
	/*
	public static void main(String[] args) throws IOException {
		String path = "H:\\Master\\Project\\Datas\\Program_data\\SAND";
        File file = new File(path);
        String[] fileList = file.list();
        for(int i = 0;i < fileList.length;i++){
            String string = fileList[i];
            //File("documentName","fileName")��File����һ��������
            File fl = new File(file.getPath(),string);
            String name = fl.getName();
            String outputDir = fl.getAbsolutePath() + "\\" ;
            if(fl.isDirectory()){
                String[] javaFile = fl.list();
                for(int j = 0;j < javaFile.length;j++){
                    if (!(javaFile[j].equals("AbstractTestCase.java") || javaFile[j].equals("AbstractTestCaseBase.java") || javaFile[j].equals("IO.java")) && javaFile[j].indexOf(".java") != -1 && javaFile[j].indexOf(".dot") == -1){
                        File f = new File(fl.getPath(),javaFile[j]);
                        //String FilePath = "H:\\Master\\Project\\Datas\\Program_data\\SAND\\248723\\CWE190_Integer_Overflow__byte_console_readLine_postinc_01.java";
                		//String outputDir = ".\\output\\";
                		//File f = new File(FilePath);
                		ASTGenerator astGenerator = new ASTGenerator(f);
                		List<MyMethodNode> methodNodeList = astGenerator.getMethodNodeList();
                		for (MyMethodNode m : methodNodeList) {
                			String dotStr = ASTtoDOT.ASTtoDotParser(m);
                			FileUtil.writeFile(outputDir + f.getName() + "_" + m.methodNode.getName() + ".dot", dotStr);
                		}
                		System.out.println("Done.");

                    }
                }
            }
        }
        */
//		String FilePath = "H:\\Master\\Project\\Datas\\Program_data\\SAND\\248723\\CWE190_Integer_Overflow__byte_console_readLine_postinc_01.java";
//		String outputDir = ".\\output\\";
//		File f = new File(FilePath);
//		ASTGenerator astGenerator = new ASTGenerator(f);
//		List<MyMethodNode> methodNodeList = astGenerator.getMethodNodeList();
//		for (MyMethodNode m : methodNodeList) {
//			String dotStr = ASTtoDOT.ASTtoDotParser(m);
//			FileUtil.writeFile(outputDir + f.getName() + "_" + m.methodNode.getName() + ".dot", dotStr);
//		}
//		System.out.println("Done.");
//	}
}
