package com.propertygraph.cfg.node;

import com.propertygraph.pe.VariableInfo;

public class CFGParameterNode extends CFGNode<VariableInfo> {

	private CFGParameterNode(final VariableInfo variable) {
		super(variable);
	}
}
