package com.generatepdg.cfg.node;

import com.generatepdg.pe.StatementInfo;

public class CFGBreakStatementNode extends CFGJumpStatementNode {

	public CFGBreakStatementNode(final StatementInfo breakStatement) {
		super(breakStatement);
	}
}
