package com.platform.astdemo.generator;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.jdt.core.dom.AST;
import org.eclipse.jdt.core.dom.ASTNode;
import org.eclipse.jdt.core.dom.ASTParser;
import org.eclipse.jdt.core.dom.CompilationUnit;
import org.eclipse.jdt.core.dom.MethodDeclaration;
import com.platform.astdemo.generator.MethodNodeVisitor;
import com.platform.astdemo.structure.MyMethodNode;
import com.platform.astdemo.structure.MyASTNode;
import com.platform.astdemo.util.FileUtil;

public class ASTGenerator {

	public List<MyMethodNode> methodNodeList = new ArrayList<MyMethodNode>();

	public ASTGenerator(File f) {
		ParseFile(f);
	}

	/**
	 * get function for methodNodeList
	 * @return
	 */
	public List<MyMethodNode> getMethodNodeList() {
		return methodNodeList;
	}

	/**
	 * use ASTParse to parse string
	 * @param srcStr
	 */
	public void parse(String srcStr) {
		ASTParser parser = ASTParser.newParser(AST.JLS3);
		parser.setSource(srcStr.toCharArray());
		parser.setKind(ASTParser.K_COMPILATION_UNIT);

		final CompilationUnit cu = (CompilationUnit) parser.createAST(null);

		// find the MethodDeclaration node, MethodNodeVisitor
		MethodNodeVisitor methodNodeVisitor = new MethodNodeVisitor();
		cu.accept(methodNodeVisitor);
		// traverse all child nodes, NodeVisitor
		for (MethodDeclaration m : methodNodeVisitor.getMethodDecs()) {
			MyMethodNode mNode = new MyMethodNode();
			mNode.methodNode = m;
			NodeVisitor nv = new NodeVisitor();
			m.accept(nv);
			List<ASTNode> astnodes = nv.getASTNodes();
			for (ASTNode node : astnodes) {
				MyASTNode myNode = new MyASTNode();
				myNode.astNode = node;
				myNode.startLineNum = cu.getLineNumber(node.getStartPosition());
				myNode.endLineNum = cu.getLineNumber(node.getStartPosition()+node.getLength());
				// add to nodeList
				mNode.nodeList.add(myNode);
				// add to mapping
				// in case, I need to exclude root node
				if (node.equals(m)) {
					continue;
				}
				int pHashcode = node.getParent().hashCode();
				int hashcode = node.hashCode();
				int[] link = { pHashcode, hashcode };
				mNode.mapping.add(link);
			}
			methodNodeList.add(mNode);
		}
		// System.out.print(ast);
	}

	public void ParseFile(File f) {
		String filePath = f.getAbsolutePath();
		if (f.isFile()) {
			try {
				parse(FileUtil.readFileToString(filePath));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			System.out.println("Not a File!");
		}
	}
}
