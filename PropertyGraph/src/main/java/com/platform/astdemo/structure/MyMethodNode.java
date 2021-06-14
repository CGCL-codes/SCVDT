package com.platform.astdemo.structure;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jdt.core.dom.MethodDeclaration;
import com.platform.astdemo.structure.MyASTNode;

public class MyMethodNode {

	public MethodDeclaration methodNode = null;
	public List<MyASTNode> nodeList = null;

	public List<int[]> mapping = null;

	public MyMethodNode() {
		this.methodNode = null;
		this.nodeList = new ArrayList<MyASTNode>();
		this.mapping = new ArrayList<int[]>();
	}

}
