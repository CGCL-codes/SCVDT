package com.propertygraph.cfg.node;

import com.propertygraph.pe.StatementInfo;

public class CFGBreakStatementNode extends CFGJumpStatementNode {

	public CFGBreakStatementNode(final StatementInfo breakStatement) {
		super(breakStatement);
	}
}
