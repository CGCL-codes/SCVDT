package com.generatepdg.cfg.node;

import com.generatepdg.pe.StatementInfo;

abstract public class CFGJumpStatementNode extends CFGStatementNode {

	CFGJumpStatementNode(final StatementInfo jumpStatement) {
		super(jumpStatement);
	}
}
