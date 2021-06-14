package com.propertygraph.cfg.node;

import com.propertygraph.pe.StatementInfo;

abstract public class CFGJumpStatementNode extends CFGStatementNode {

	CFGJumpStatementNode(final StatementInfo jumpStatement) {
		super(jumpStatement);
	}
}
