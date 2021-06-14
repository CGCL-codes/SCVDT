package com.generatepdg.pdg.node;

import com.generatepdg.pe.ExpressionInfo;
import com.generatepdg.pe.MethodInfo;
import com.generatepdg.pe.ProgramElementInfo;

public class PDGMethodEnterNode extends PDGControlNode {

	static public PDGMethodEnterNode getInstance(final MethodInfo method) {
		assert null != method : "\"method\" is null.";
		final ProgramElementInfo methodEnterExpression = new ExpressionInfo(
				ExpressionInfo.CATEGORY.MethodEnter, method.startLine,
				method.endLine);
		methodEnterExpression.setText("Enter");
		return new PDGMethodEnterNode(methodEnterExpression);
	}

	private PDGMethodEnterNode(final ProgramElementInfo methodEnterExpression) {
		super(methodEnterExpression);
	}
}
