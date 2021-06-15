// Generated from main/resources/JavaScriptParser.g4 by ANTLR 4.7
package edu.berkeley.cs.jqf.fuzz.LM.antlr4.main.resources;
import edu.berkeley.cs.jqf.fuzz.LM.Base.JavaScriptParserBase;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast"})
public class JavaScriptParser extends JavaScriptParserBase {
	static { RuntimeMetaData.checkVersion("4.7", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		HashBangLine=1, MultiLineComment=2, SingleLineComment=3, RegularExpressionLiteral=4, 
		OpenBracket=5, CloseBracket=6, OpenParen=7, CloseParen=8, OpenBrace=9, 
		CloseBrace=10, SemiColon=11, Comma=12, Assign=13, QuestionMark=14, Colon=15, 
		Ellipsis=16, Dot=17, PlusPlus=18, MinusMinus=19, Plus=20, Minus=21, BitNot=22, 
		Not=23, Multiply=24, Divide=25, Modulus=26, Power=27, NullCoalesce=28, 
		Hashtag=29, RightShiftArithmetic=30, LeftShiftArithmetic=31, RightShiftLogical=32, 
		LessThan=33, MoreThan=34, LessThanEquals=35, GreaterThanEquals=36, Equals_=37, 
		NotEquals=38, IdentityEquals=39, IdentityNotEquals=40, BitAnd=41, BitXOr=42, 
		BitOr=43, And=44, Or=45, MultiplyAssign=46, DivideAssign=47, ModulusAssign=48, 
		PlusAssign=49, MinusAssign=50, LeftShiftArithmeticAssign=51, RightShiftArithmeticAssign=52, 
		RightShiftLogicalAssign=53, BitAndAssign=54, BitXorAssign=55, BitOrAssign=56, 
		PowerAssign=57, ARROW=58, NullLiteral=59, BooleanLiteral=60, DecimalLiteral=61, 
		HexIntegerLiteral=62, OctalIntegerLiteral=63, OctalIntegerLiteral2=64, 
		BinaryIntegerLiteral=65, BigHexIntegerLiteral=66, BigOctalIntegerLiteral=67, 
		BigBinaryIntegerLiteral=68, BigDecimalIntegerLiteral=69, Break=70, Do=71, 
		Instanceof=72, Typeof=73, Case=74, Else=75, New=76, Var=77, Catch=78, 
		Finally=79, Return=80, Void=81, Continue=82, For=83, Switch=84, While=85, 
		Debugger=86, Function=87, This=88, With=89, Default=90, If=91, Throw=92, 
		Delete=93, In=94, Try=95, As=96, From=97, Class=98, Enum=99, Extends=100, 
		Super=101, Const=102, Export=103, Import=104, Async=105, Await=106, Implements=107, 
		StrictLet=108, NonStrictLet=109, Private=110, Public=111, Interface=112, 
		Package=113, Protected=114, Static=115, Yield=116, Identifier=117, StringLiteral=118, 
		TemplateStringLiteral=119, WhiteSpaces=120, LineTerminator=121, HtmlComment=122, 
		CDataComment=123, UnexpectedCharacter=124;
	public static final int
		RULE_program = 0, RULE_sourceElement = 1, RULE_statement = 2, RULE_block = 3, 
		RULE_statementList = 4, RULE_importStatement = 5, RULE_importFromBlock = 6, 
		RULE_moduleItems = 7, RULE_importDefault = 8, RULE_importNamespace = 9, 
		RULE_importFrom = 10, RULE_aliasName = 11, RULE_exportStatement = 12, 
		RULE_exportFromBlock = 13, RULE_declaration = 14, RULE_variableStatement = 15, 
		RULE_variableDeclarationList = 16, RULE_variableDeclaration = 17, RULE_emptyStatement = 18, 
		RULE_expressionStatement = 19, RULE_ifStatement = 20, RULE_iterationStatement = 21, 
		RULE_varModifier = 22, RULE_continueStatement = 23, RULE_breakStatement = 24, 
		RULE_returnStatement = 25, RULE_yieldStatement = 26, RULE_withStatement = 27, 
		RULE_switchStatement = 28, RULE_caseBlock = 29, RULE_caseClauses = 30, 
		RULE_caseClause = 31, RULE_defaultClause = 32, RULE_labelledStatement = 33, 
		RULE_throwStatement = 34, RULE_tryStatement = 35, RULE_catchProduction = 36, 
		RULE_finallyProduction = 37, RULE_debuggerStatement = 38, RULE_functionDeclaration = 39, 
		RULE_classDeclaration = 40, RULE_classTail = 41, RULE_classElement = 42, 
		RULE_methodDefinition = 43, RULE_formalParameterList = 44, RULE_formalParameterArg = 45, 
		RULE_lastFormalParameterArg = 46, RULE_functionBody = 47, RULE_sourceElements = 48, 
		RULE_arrayLiteral = 49, RULE_elementList = 50, RULE_arrayElement = 51, 
		RULE_propertyAssignment = 52, RULE_propertyName = 53, RULE_arguments = 54, 
		RULE_argument = 55, RULE_expressionSequence = 56, RULE_singleExpression = 57, 
		RULE_assignable = 58, RULE_objectLiteral = 59, RULE_anoymousFunction = 60, 
		RULE_arrowFunctionParameters = 61, RULE_arrowFunctionBody = 62, RULE_assignmentOperator = 63, 
		RULE_literal = 64, RULE_numericLiteral = 65, RULE_bigintLiteral = 66, 
		RULE_getter = 67, RULE_setter = 68, RULE_identifierName = 69, RULE_identifier = 70, 
		RULE_reservedWord = 71, RULE_keyword = 72, RULE_let = 73, RULE_eos = 74;
	public static final String[] ruleNames = {
		"program", "sourceElement", "statement", "block", "statementList", "importStatement", 
		"importFromBlock", "moduleItems", "importDefault", "importNamespace", 
		"importFrom", "aliasName", "exportStatement", "exportFromBlock", "declaration", 
		"variableStatement", "variableDeclarationList", "variableDeclaration", 
		"emptyStatement", "expressionStatement", "ifStatement", "iterationStatement", 
		"varModifier", "continueStatement", "breakStatement", "returnStatement", 
		"yieldStatement", "withStatement", "switchStatement", "caseBlock", "caseClauses", 
		"caseClause", "defaultClause", "labelledStatement", "throwStatement", 
		"tryStatement", "catchProduction", "finallyProduction", "debuggerStatement", 
		"functionDeclaration", "classDeclaration", "classTail", "classElement", 
		"methodDefinition", "formalParameterList", "formalParameterArg", "lastFormalParameterArg", 
		"functionBody", "sourceElements", "arrayLiteral", "elementList", "arrayElement", 
		"propertyAssignment", "propertyName", "arguments", "argument", "expressionSequence", 
		"singleExpression", "assignable", "objectLiteral", "anoymousFunction", 
		"arrowFunctionParameters", "arrowFunctionBody", "assignmentOperator", 
		"literal", "numericLiteral", "bigintLiteral", "getter", "setter", "identifierName", 
		"identifier", "reservedWord", "keyword", "let", "eos"
	};

	private static final String[] _LITERAL_NAMES = {
		null, null, null, null, null, "'['", "']'", "'('", "')'", "'{'", "'}'", 
		"';'", "','", "'='", "'?'", "':'", "'...'", "'.'", "'++'", "'--'", "'+'", 
		"'-'", "'~'", "'!'", "'*'", "'/'", "'%'", "'**'", "'??'", "'#'", "'>>'", 
		"'<<'", "'>>>'", "'<'", "'>'", "'<='", "'>='", "'=='", "'!='", "'==='", 
		"'!=='", "'&'", "'^'", "'|'", "'&&'", "'||'", "'*='", "'/='", "'%='", 
		"'+='", "'-='", "'<<='", "'>>='", "'>>>='", "'&='", "'^='", "'|='", "'**='", 
		"'=>'", "'null'", null, null, null, null, null, null, null, null, null, 
		null, "'break'", "'do'", "'instanceof'", "'typeof'", "'case'", "'else'", 
		"'new'", "'var'", "'catch'", "'finally'", "'return'", "'void'", "'continue'", 
		"'for'", "'switch'", "'while'", "'debugger'", "'function'", "'this'", 
		"'with'", "'default'", "'if'", "'throw'", "'delete'", "'in'", "'try'", 
		"'as'", "'from'", "'class'", "'enum'", "'extends'", "'super'", "'const'", 
		"'export'", "'import'", "'async'", "'await'", "'implements'", null, null, 
		"'private'", "'public'", "'interface'", "'package'", "'protected'", "'static'", 
		"'yield'"
	};
	private static final String[] _SYMBOLIC_NAMES = {
		null, "HashBangLine", "MultiLineComment", "SingleLineComment", "RegularExpressionLiteral", 
		"OpenBracket", "CloseBracket", "OpenParen", "CloseParen", "OpenBrace", 
		"CloseBrace", "SemiColon", "Comma", "Assign", "QuestionMark", "Colon", 
		"Ellipsis", "Dot", "PlusPlus", "MinusMinus", "Plus", "Minus", "BitNot", 
		"Not", "Multiply", "Divide", "Modulus", "Power", "NullCoalesce", "Hashtag", 
		"RightShiftArithmetic", "LeftShiftArithmetic", "RightShiftLogical", "LessThan", 
		"MoreThan", "LessThanEquals", "GreaterThanEquals", "Equals_", "NotEquals", 
		"IdentityEquals", "IdentityNotEquals", "BitAnd", "BitXOr", "BitOr", "And", 
		"Or", "MultiplyAssign", "DivideAssign", "ModulusAssign", "PlusAssign", 
		"MinusAssign", "LeftShiftArithmeticAssign", "RightShiftArithmeticAssign", 
		"RightShiftLogicalAssign", "BitAndAssign", "BitXorAssign", "BitOrAssign", 
		"PowerAssign", "ARROW", "NullLiteral", "BooleanLiteral", "DecimalLiteral", 
		"HexIntegerLiteral", "OctalIntegerLiteral", "OctalIntegerLiteral2", "BinaryIntegerLiteral", 
		"BigHexIntegerLiteral", "BigOctalIntegerLiteral", "BigBinaryIntegerLiteral", 
		"BigDecimalIntegerLiteral", "Break", "Do", "Instanceof", "Typeof", "Case", 
		"Else", "New", "Var", "Catch", "Finally", "Return", "Void", "Continue", 
		"For", "Switch", "While", "Debugger", "Function", "This", "With", "Default", 
		"If", "Throw", "Delete", "In", "Try", "As", "From", "Class", "Enum", "Extends", 
		"Super", "Const", "Export", "Import", "Async", "Await", "Implements", 
		"StrictLet", "NonStrictLet", "Private", "Public", "Interface", "Package", 
		"Protected", "Static", "Yield", "Identifier", "StringLiteral", "TemplateStringLiteral", 
		"WhiteSpaces", "LineTerminator", "HtmlComment", "CDataComment", "UnexpectedCharacter"
	};
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "JavaScriptParser.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public JavaScriptParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}
	public static class ProgramContext extends ParserRuleContext {
		public TerminalNode EOF() { return getToken(JavaScriptParser.EOF, 0); }
		public TerminalNode HashBangLine() { return getToken(JavaScriptParser.HashBangLine, 0); }
		public SourceElementsContext sourceElements() {
			return getRuleContext(SourceElementsContext.class,0);
		}
		public ProgramContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_program; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterProgram(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitProgram(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitProgram(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ProgramContext program() throws RecognitionException {
		ProgramContext _localctx = new ProgramContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_program);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(151);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,0,_ctx) ) {
			case 1:
				{
				setState(150);
				match(HashBangLine);
				}
				break;
			}
			setState(154);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,1,_ctx) ) {
			case 1:
				{
				setState(153);
				sourceElements();
				}
				break;
			}
			setState(156);
			match(EOF);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SourceElementContext extends ParserRuleContext {
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public SourceElementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sourceElement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterSourceElement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitSourceElement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitSourceElement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SourceElementContext sourceElement() throws RecognitionException {
		SourceElementContext _localctx = new SourceElementContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_sourceElement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(158);
			statement();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class StatementContext extends ParserRuleContext {
		public BlockContext block() {
			return getRuleContext(BlockContext.class,0);
		}
		public VariableStatementContext variableStatement() {
			return getRuleContext(VariableStatementContext.class,0);
		}
		public ImportStatementContext importStatement() {
			return getRuleContext(ImportStatementContext.class,0);
		}
		public ExportStatementContext exportStatement() {
			return getRuleContext(ExportStatementContext.class,0);
		}
		public EmptyStatementContext emptyStatement() {
			return getRuleContext(EmptyStatementContext.class,0);
		}
		public ClassDeclarationContext classDeclaration() {
			return getRuleContext(ClassDeclarationContext.class,0);
		}
		public ExpressionStatementContext expressionStatement() {
			return getRuleContext(ExpressionStatementContext.class,0);
		}
		public IfStatementContext ifStatement() {
			return getRuleContext(IfStatementContext.class,0);
		}
		public IterationStatementContext iterationStatement() {
			return getRuleContext(IterationStatementContext.class,0);
		}
		public ContinueStatementContext continueStatement() {
			return getRuleContext(ContinueStatementContext.class,0);
		}
		public BreakStatementContext breakStatement() {
			return getRuleContext(BreakStatementContext.class,0);
		}
		public ReturnStatementContext returnStatement() {
			return getRuleContext(ReturnStatementContext.class,0);
		}
		public YieldStatementContext yieldStatement() {
			return getRuleContext(YieldStatementContext.class,0);
		}
		public WithStatementContext withStatement() {
			return getRuleContext(WithStatementContext.class,0);
		}
		public LabelledStatementContext labelledStatement() {
			return getRuleContext(LabelledStatementContext.class,0);
		}
		public SwitchStatementContext switchStatement() {
			return getRuleContext(SwitchStatementContext.class,0);
		}
		public ThrowStatementContext throwStatement() {
			return getRuleContext(ThrowStatementContext.class,0);
		}
		public TryStatementContext tryStatement() {
			return getRuleContext(TryStatementContext.class,0);
		}
		public DebuggerStatementContext debuggerStatement() {
			return getRuleContext(DebuggerStatementContext.class,0);
		}
		public FunctionDeclarationContext functionDeclaration() {
			return getRuleContext(FunctionDeclarationContext.class,0);
		}
		public StatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_statement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final StatementContext statement() throws RecognitionException {
		StatementContext _localctx = new StatementContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_statement);
		try {
			setState(180);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,2,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(160);
				block();
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(161);
				variableStatement();
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				setState(162);
				importStatement();
				}
				break;
			case 4:
				enterOuterAlt(_localctx, 4);
				{
				setState(163);
				exportStatement();
				}
				break;
			case 5:
				enterOuterAlt(_localctx, 5);
				{
				setState(164);
				emptyStatement();
				}
				break;
			case 6:
				enterOuterAlt(_localctx, 6);
				{
				setState(165);
				classDeclaration();
				}
				break;
			case 7:
				enterOuterAlt(_localctx, 7);
				{
				setState(166);
				expressionStatement();
				}
				break;
			case 8:
				enterOuterAlt(_localctx, 8);
				{
				setState(167);
				ifStatement();
				}
				break;
			case 9:
				enterOuterAlt(_localctx, 9);
				{
				setState(168);
				iterationStatement();
				}
				break;
			case 10:
				enterOuterAlt(_localctx, 10);
				{
				setState(169);
				continueStatement();
				}
				break;
			case 11:
				enterOuterAlt(_localctx, 11);
				{
				setState(170);
				breakStatement();
				}
				break;
			case 12:
				enterOuterAlt(_localctx, 12);
				{
				setState(171);
				returnStatement();
				}
				break;
			case 13:
				enterOuterAlt(_localctx, 13);
				{
				setState(172);
				yieldStatement();
				}
				break;
			case 14:
				enterOuterAlt(_localctx, 14);
				{
				setState(173);
				withStatement();
				}
				break;
			case 15:
				enterOuterAlt(_localctx, 15);
				{
				setState(174);
				labelledStatement();
				}
				break;
			case 16:
				enterOuterAlt(_localctx, 16);
				{
				setState(175);
				switchStatement();
				}
				break;
			case 17:
				enterOuterAlt(_localctx, 17);
				{
				setState(176);
				throwStatement();
				}
				break;
			case 18:
				enterOuterAlt(_localctx, 18);
				{
				setState(177);
				tryStatement();
				}
				break;
			case 19:
				enterOuterAlt(_localctx, 19);
				{
				setState(178);
				debuggerStatement();
				}
				break;
			case 20:
				enterOuterAlt(_localctx, 20);
				{
				setState(179);
				functionDeclaration();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class BlockContext extends ParserRuleContext {
		public StatementListContext statementList() {
			return getRuleContext(StatementListContext.class,0);
		}
		public BlockContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_block; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBlock(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBlock(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBlock(this);
			else return visitor.visitChildren(this);
		}
	}

	public final BlockContext block() throws RecognitionException {
		BlockContext _localctx = new BlockContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_block);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(182);
			match(OpenBrace);
			setState(184);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,3,_ctx) ) {
			case 1:
				{
				setState(183);
				statementList();
				}
				break;
			}
			setState(186);
			match(CloseBrace);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class StatementListContext extends ParserRuleContext {
		public List<StatementContext> statement() {
			return getRuleContexts(StatementContext.class);
		}
		public StatementContext statement(int i) {
			return getRuleContext(StatementContext.class,i);
		}
		public StatementListContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_statementList; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterStatementList(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitStatementList(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitStatementList(this);
			else return visitor.visitChildren(this);
		}
	}

	public final StatementListContext statementList() throws RecognitionException {
		StatementListContext _localctx = new StatementListContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_statementList);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(189); 
			_errHandler.sync(this);
			_alt = 1;
			do {
				switch (_alt) {
				case 1:
					{
					{
					setState(188);
					statement();
					}
					}
					break;
				default:
					throw new NoViableAltException(this);
				}
				setState(191); 
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,4,_ctx);
			} while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER );
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ImportStatementContext extends ParserRuleContext {
		public TerminalNode Import() { return getToken(JavaScriptParser.Import, 0); }
		public ImportFromBlockContext importFromBlock() {
			return getRuleContext(ImportFromBlockContext.class,0);
		}
		public ImportStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_importStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterImportStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitImportStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitImportStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ImportStatementContext importStatement() throws RecognitionException {
		ImportStatementContext _localctx = new ImportStatementContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_importStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(193);
			match(Import);
			setState(194);
			importFromBlock();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ImportFromBlockContext extends ParserRuleContext {
		public ImportFromContext importFrom() {
			return getRuleContext(ImportFromContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ImportNamespaceContext importNamespace() {
			return getRuleContext(ImportNamespaceContext.class,0);
		}
		public ModuleItemsContext moduleItems() {
			return getRuleContext(ModuleItemsContext.class,0);
		}
		public ImportDefaultContext importDefault() {
			return getRuleContext(ImportDefaultContext.class,0);
		}
		public TerminalNode StringLiteral() { return getToken(JavaScriptParser.StringLiteral, 0); }
		public ImportFromBlockContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_importFromBlock; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterImportFromBlock(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitImportFromBlock(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitImportFromBlock(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ImportFromBlockContext importFromBlock() throws RecognitionException {
		ImportFromBlockContext _localctx = new ImportFromBlockContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_importFromBlock);
		try {
			setState(208);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case OpenBrace:
			case Multiply:
			case NullLiteral:
			case BooleanLiteral:
			case Break:
			case Do:
			case Instanceof:
			case Typeof:
			case Case:
			case Else:
			case New:
			case Var:
			case Catch:
			case Finally:
			case Return:
			case Void:
			case Continue:
			case For:
			case Switch:
			case While:
			case Debugger:
			case Function:
			case This:
			case With:
			case Default:
			case If:
			case Throw:
			case Delete:
			case In:
			case Try:
			case As:
			case From:
			case Class:
			case Enum:
			case Extends:
			case Super:
			case Const:
			case Export:
			case Import:
			case Async:
			case Await:
			case Implements:
			case StrictLet:
			case NonStrictLet:
			case Private:
			case Public:
			case Interface:
			case Package:
			case Protected:
			case Static:
			case Yield:
			case Identifier:
				enterOuterAlt(_localctx, 1);
				{
				setState(197);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,5,_ctx) ) {
				case 1:
					{
					setState(196);
					importDefault();
					}
					break;
				}
				setState(201);
				_errHandler.sync(this);
				switch (_input.LA(1)) {
				case Multiply:
				case NullLiteral:
				case BooleanLiteral:
				case Break:
				case Do:
				case Instanceof:
				case Typeof:
				case Case:
				case Else:
				case New:
				case Var:
				case Catch:
				case Finally:
				case Return:
				case Void:
				case Continue:
				case For:
				case Switch:
				case While:
				case Debugger:
				case Function:
				case This:
				case With:
				case Default:
				case If:
				case Throw:
				case Delete:
				case In:
				case Try:
				case As:
				case From:
				case Class:
				case Enum:
				case Extends:
				case Super:
				case Const:
				case Export:
				case Import:
				case Async:
				case Await:
				case Implements:
				case StrictLet:
				case NonStrictLet:
				case Private:
				case Public:
				case Interface:
				case Package:
				case Protected:
				case Static:
				case Yield:
				case Identifier:
					{
					setState(199);
					importNamespace();
					}
					break;
				case OpenBrace:
					{
					setState(200);
					moduleItems();
					}
					break;
				default:
					throw new NoViableAltException(this);
				}
				setState(203);
				importFrom();
				setState(204);
				eos();
				}
				break;
			case StringLiteral:
				enterOuterAlt(_localctx, 2);
				{
				setState(206);
				match(StringLiteral);
				setState(207);
				eos();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ModuleItemsContext extends ParserRuleContext {
		public List<AliasNameContext> aliasName() {
			return getRuleContexts(AliasNameContext.class);
		}
		public AliasNameContext aliasName(int i) {
			return getRuleContext(AliasNameContext.class,i);
		}
		public ModuleItemsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_moduleItems; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterModuleItems(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitModuleItems(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitModuleItems(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ModuleItemsContext moduleItems() throws RecognitionException {
		ModuleItemsContext _localctx = new ModuleItemsContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_moduleItems);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(210);
			match(OpenBrace);
			setState(216);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,8,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(211);
					aliasName();
					setState(212);
					match(Comma);
					}
					} 
				}
				setState(218);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,8,_ctx);
			}
			setState(223);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (((((_la - 59)) & ~0x3f) == 0 && ((1L << (_la - 59)) & ((1L << (NullLiteral - 59)) | (1L << (BooleanLiteral - 59)) | (1L << (Break - 59)) | (1L << (Do - 59)) | (1L << (Instanceof - 59)) | (1L << (Typeof - 59)) | (1L << (Case - 59)) | (1L << (Else - 59)) | (1L << (New - 59)) | (1L << (Var - 59)) | (1L << (Catch - 59)) | (1L << (Finally - 59)) | (1L << (Return - 59)) | (1L << (Void - 59)) | (1L << (Continue - 59)) | (1L << (For - 59)) | (1L << (Switch - 59)) | (1L << (While - 59)) | (1L << (Debugger - 59)) | (1L << (Function - 59)) | (1L << (This - 59)) | (1L << (With - 59)) | (1L << (Default - 59)) | (1L << (If - 59)) | (1L << (Throw - 59)) | (1L << (Delete - 59)) | (1L << (In - 59)) | (1L << (Try - 59)) | (1L << (As - 59)) | (1L << (From - 59)) | (1L << (Class - 59)) | (1L << (Enum - 59)) | (1L << (Extends - 59)) | (1L << (Super - 59)) | (1L << (Const - 59)) | (1L << (Export - 59)) | (1L << (Import - 59)) | (1L << (Async - 59)) | (1L << (Await - 59)) | (1L << (Implements - 59)) | (1L << (StrictLet - 59)) | (1L << (NonStrictLet - 59)) | (1L << (Private - 59)) | (1L << (Public - 59)) | (1L << (Interface - 59)) | (1L << (Package - 59)) | (1L << (Protected - 59)) | (1L << (Static - 59)) | (1L << (Yield - 59)) | (1L << (Identifier - 59)))) != 0)) {
				{
				setState(219);
				aliasName();
				setState(221);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Comma) {
					{
					setState(220);
					match(Comma);
					}
				}

				}
			}

			setState(225);
			match(CloseBrace);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ImportDefaultContext extends ParserRuleContext {
		public AliasNameContext aliasName() {
			return getRuleContext(AliasNameContext.class,0);
		}
		public ImportDefaultContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_importDefault; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterImportDefault(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitImportDefault(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitImportDefault(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ImportDefaultContext importDefault() throws RecognitionException {
		ImportDefaultContext _localctx = new ImportDefaultContext(_ctx, getState());
		enterRule(_localctx, 16, RULE_importDefault);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(227);
			aliasName();
			setState(228);
			match(Comma);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ImportNamespaceContext extends ParserRuleContext {
		public List<IdentifierNameContext> identifierName() {
			return getRuleContexts(IdentifierNameContext.class);
		}
		public IdentifierNameContext identifierName(int i) {
			return getRuleContext(IdentifierNameContext.class,i);
		}
		public TerminalNode As() { return getToken(JavaScriptParser.As, 0); }
		public ImportNamespaceContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_importNamespace; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterImportNamespace(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitImportNamespace(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitImportNamespace(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ImportNamespaceContext importNamespace() throws RecognitionException {
		ImportNamespaceContext _localctx = new ImportNamespaceContext(_ctx, getState());
		enterRule(_localctx, 18, RULE_importNamespace);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(232);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Multiply:
				{
				setState(230);
				match(Multiply);
				}
				break;
			case NullLiteral:
			case BooleanLiteral:
			case Break:
			case Do:
			case Instanceof:
			case Typeof:
			case Case:
			case Else:
			case New:
			case Var:
			case Catch:
			case Finally:
			case Return:
			case Void:
			case Continue:
			case For:
			case Switch:
			case While:
			case Debugger:
			case Function:
			case This:
			case With:
			case Default:
			case If:
			case Throw:
			case Delete:
			case In:
			case Try:
			case As:
			case From:
			case Class:
			case Enum:
			case Extends:
			case Super:
			case Const:
			case Export:
			case Import:
			case Async:
			case Await:
			case Implements:
			case StrictLet:
			case NonStrictLet:
			case Private:
			case Public:
			case Interface:
			case Package:
			case Protected:
			case Static:
			case Yield:
			case Identifier:
				{
				setState(231);
				identifierName();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			setState(236);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==As) {
				{
				setState(234);
				match(As);
				setState(235);
				identifierName();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ImportFromContext extends ParserRuleContext {
		public TerminalNode From() { return getToken(JavaScriptParser.From, 0); }
		public TerminalNode StringLiteral() { return getToken(JavaScriptParser.StringLiteral, 0); }
		public ImportFromContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_importFrom; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterImportFrom(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitImportFrom(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitImportFrom(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ImportFromContext importFrom() throws RecognitionException {
		ImportFromContext _localctx = new ImportFromContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_importFrom);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(238);
			match(From);
			setState(239);
			match(StringLiteral);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class AliasNameContext extends ParserRuleContext {
		public List<IdentifierNameContext> identifierName() {
			return getRuleContexts(IdentifierNameContext.class);
		}
		public IdentifierNameContext identifierName(int i) {
			return getRuleContext(IdentifierNameContext.class,i);
		}
		public TerminalNode As() { return getToken(JavaScriptParser.As, 0); }
		public AliasNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_aliasName; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAliasName(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAliasName(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAliasName(this);
			else return visitor.visitChildren(this);
		}
	}

	public final AliasNameContext aliasName() throws RecognitionException {
		AliasNameContext _localctx = new AliasNameContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_aliasName);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(241);
			identifierName();
			setState(244);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==As) {
				{
				setState(242);
				match(As);
				setState(243);
				identifierName();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ExportStatementContext extends ParserRuleContext {
		public ExportStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_exportStatement; }
	 
		public ExportStatementContext() { }
		public void copyFrom(ExportStatementContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class ExportDefaultDeclarationContext extends ExportStatementContext {
		public TerminalNode Export() { return getToken(JavaScriptParser.Export, 0); }
		public TerminalNode Default() { return getToken(JavaScriptParser.Default, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ExportDefaultDeclarationContext(ExportStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterExportDefaultDeclaration(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitExportDefaultDeclaration(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitExportDefaultDeclaration(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ExportDeclarationContext extends ExportStatementContext {
		public TerminalNode Export() { return getToken(JavaScriptParser.Export, 0); }
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ExportFromBlockContext exportFromBlock() {
			return getRuleContext(ExportFromBlockContext.class,0);
		}
		public DeclarationContext declaration() {
			return getRuleContext(DeclarationContext.class,0);
		}
		public ExportDeclarationContext(ExportStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterExportDeclaration(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitExportDeclaration(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitExportDeclaration(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ExportStatementContext exportStatement() throws RecognitionException {
		ExportStatementContext _localctx = new ExportStatementContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_exportStatement);
		try {
			setState(258);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,15,_ctx) ) {
			case 1:
				_localctx = new ExportDeclarationContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(246);
				match(Export);
				setState(249);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,14,_ctx) ) {
				case 1:
					{
					setState(247);
					exportFromBlock();
					}
					break;
				case 2:
					{
					setState(248);
					declaration();
					}
					break;
				}
				setState(251);
				eos();
				}
				break;
			case 2:
				_localctx = new ExportDefaultDeclarationContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(253);
				match(Export);
				setState(254);
				match(Default);
				setState(255);
				singleExpression(0);
				setState(256);
				eos();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ExportFromBlockContext extends ParserRuleContext {
		public ImportNamespaceContext importNamespace() {
			return getRuleContext(ImportNamespaceContext.class,0);
		}
		public ImportFromContext importFrom() {
			return getRuleContext(ImportFromContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ModuleItemsContext moduleItems() {
			return getRuleContext(ModuleItemsContext.class,0);
		}
		public ExportFromBlockContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_exportFromBlock; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterExportFromBlock(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitExportFromBlock(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitExportFromBlock(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ExportFromBlockContext exportFromBlock() throws RecognitionException {
		ExportFromBlockContext _localctx = new ExportFromBlockContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_exportFromBlock);
		try {
			setState(270);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Multiply:
			case NullLiteral:
			case BooleanLiteral:
			case Break:
			case Do:
			case Instanceof:
			case Typeof:
			case Case:
			case Else:
			case New:
			case Var:
			case Catch:
			case Finally:
			case Return:
			case Void:
			case Continue:
			case For:
			case Switch:
			case While:
			case Debugger:
			case Function:
			case This:
			case With:
			case Default:
			case If:
			case Throw:
			case Delete:
			case In:
			case Try:
			case As:
			case From:
			case Class:
			case Enum:
			case Extends:
			case Super:
			case Const:
			case Export:
			case Import:
			case Async:
			case Await:
			case Implements:
			case StrictLet:
			case NonStrictLet:
			case Private:
			case Public:
			case Interface:
			case Package:
			case Protected:
			case Static:
			case Yield:
			case Identifier:
				enterOuterAlt(_localctx, 1);
				{
				setState(260);
				importNamespace();
				setState(261);
				importFrom();
				setState(262);
				eos();
				}
				break;
			case OpenBrace:
				enterOuterAlt(_localctx, 2);
				{
				setState(264);
				moduleItems();
				setState(266);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,16,_ctx) ) {
				case 1:
					{
					setState(265);
					importFrom();
					}
					break;
				}
				setState(268);
				eos();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DeclarationContext extends ParserRuleContext {
		public VariableStatementContext variableStatement() {
			return getRuleContext(VariableStatementContext.class,0);
		}
		public ClassDeclarationContext classDeclaration() {
			return getRuleContext(ClassDeclarationContext.class,0);
		}
		public FunctionDeclarationContext functionDeclaration() {
			return getRuleContext(FunctionDeclarationContext.class,0);
		}
		public DeclarationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_declaration; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterDeclaration(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitDeclaration(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitDeclaration(this);
			else return visitor.visitChildren(this);
		}
	}

	public final DeclarationContext declaration() throws RecognitionException {
		DeclarationContext _localctx = new DeclarationContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_declaration);
		try {
			setState(275);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Var:
			case Const:
			case StrictLet:
			case NonStrictLet:
				enterOuterAlt(_localctx, 1);
				{
				setState(272);
				variableStatement();
				}
				break;
			case Class:
				enterOuterAlt(_localctx, 2);
				{
				setState(273);
				classDeclaration();
				}
				break;
			case Function:
			case Async:
				enterOuterAlt(_localctx, 3);
				{
				setState(274);
				functionDeclaration();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class VariableStatementContext extends ParserRuleContext {
		public VariableDeclarationListContext variableDeclarationList() {
			return getRuleContext(VariableDeclarationListContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public VariableStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_variableStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterVariableStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitVariableStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitVariableStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VariableStatementContext variableStatement() throws RecognitionException {
		VariableStatementContext _localctx = new VariableStatementContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_variableStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(277);
			variableDeclarationList();
			setState(278);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class VariableDeclarationListContext extends ParserRuleContext {
		public VarModifierContext varModifier() {
			return getRuleContext(VarModifierContext.class,0);
		}
		public List<VariableDeclarationContext> variableDeclaration() {
			return getRuleContexts(VariableDeclarationContext.class);
		}
		public VariableDeclarationContext variableDeclaration(int i) {
			return getRuleContext(VariableDeclarationContext.class,i);
		}
		public VariableDeclarationListContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_variableDeclarationList; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterVariableDeclarationList(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitVariableDeclarationList(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitVariableDeclarationList(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VariableDeclarationListContext variableDeclarationList() throws RecognitionException {
		VariableDeclarationListContext _localctx = new VariableDeclarationListContext(_ctx, getState());
		enterRule(_localctx, 32, RULE_variableDeclarationList);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(280);
			varModifier();
			setState(281);
			variableDeclaration();
			setState(286);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,19,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(282);
					match(Comma);
					setState(283);
					variableDeclaration();
					}
					} 
				}
				setState(288);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,19,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class VariableDeclarationContext extends ParserRuleContext {
		public AssignableContext assignable() {
			return getRuleContext(AssignableContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public VariableDeclarationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_variableDeclaration; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterVariableDeclaration(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitVariableDeclaration(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitVariableDeclaration(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VariableDeclarationContext variableDeclaration() throws RecognitionException {
		VariableDeclarationContext _localctx = new VariableDeclarationContext(_ctx, getState());
		enterRule(_localctx, 34, RULE_variableDeclaration);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(289);
			assignable();
			setState(292);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,20,_ctx) ) {
			case 1:
				{
				setState(290);
				match(Assign);
				setState(291);
				singleExpression(0);
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class EmptyStatementContext extends ParserRuleContext {
		public TerminalNode SemiColon() { return getToken(JavaScriptParser.SemiColon, 0); }
		public EmptyStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_emptyStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterEmptyStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitEmptyStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitEmptyStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final EmptyStatementContext emptyStatement() throws RecognitionException {
		EmptyStatementContext _localctx = new EmptyStatementContext(_ctx, getState());
		enterRule(_localctx, 36, RULE_emptyStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(294);
			match(SemiColon);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ExpressionStatementContext extends ParserRuleContext {
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ExpressionStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_expressionStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterExpressionStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitExpressionStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitExpressionStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ExpressionStatementContext expressionStatement() throws RecognitionException {
		ExpressionStatementContext _localctx = new ExpressionStatementContext(_ctx, getState());
		enterRule(_localctx, 38, RULE_expressionStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(296);
			if (!(this.notOpenBraceAndNotFunction())) throw new FailedPredicateException(this, "this.notOpenBraceAndNotFunction()");
			setState(297);
			expressionSequence();
			setState(298);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class IfStatementContext extends ParserRuleContext {
		public TerminalNode If() { return getToken(JavaScriptParser.If, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public List<StatementContext> statement() {
			return getRuleContexts(StatementContext.class);
		}
		public StatementContext statement(int i) {
			return getRuleContext(StatementContext.class,i);
		}
		public TerminalNode Else() { return getToken(JavaScriptParser.Else, 0); }
		public IfStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_ifStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterIfStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitIfStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitIfStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final IfStatementContext ifStatement() throws RecognitionException {
		IfStatementContext _localctx = new IfStatementContext(_ctx, getState());
		enterRule(_localctx, 40, RULE_ifStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(300);
			match(If);
			setState(301);
			match(OpenParen);
			setState(302);
			expressionSequence();
			setState(303);
			match(CloseParen);
			setState(304);
			statement();
			setState(307);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,21,_ctx) ) {
			case 1:
				{
				setState(305);
				match(Else);
				setState(306);
				statement();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class IterationStatementContext extends ParserRuleContext {
		public IterationStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_iterationStatement; }
	 
		public IterationStatementContext() { }
		public void copyFrom(IterationStatementContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class DoStatementContext extends IterationStatementContext {
		public TerminalNode Do() { return getToken(JavaScriptParser.Do, 0); }
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public TerminalNode While() { return getToken(JavaScriptParser.While, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public DoStatementContext(IterationStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterDoStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitDoStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitDoStatement(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class WhileStatementContext extends IterationStatementContext {
		public TerminalNode While() { return getToken(JavaScriptParser.While, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public WhileStatementContext(IterationStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterWhileStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitWhileStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitWhileStatement(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ForStatementContext extends IterationStatementContext {
		public TerminalNode For() { return getToken(JavaScriptParser.For, 0); }
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public List<ExpressionSequenceContext> expressionSequence() {
			return getRuleContexts(ExpressionSequenceContext.class);
		}
		public ExpressionSequenceContext expressionSequence(int i) {
			return getRuleContext(ExpressionSequenceContext.class,i);
		}
		public VariableDeclarationListContext variableDeclarationList() {
			return getRuleContext(VariableDeclarationListContext.class,0);
		}
		public ForStatementContext(IterationStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterForStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitForStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitForStatement(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ForInStatementContext extends IterationStatementContext {
		public TerminalNode For() { return getToken(JavaScriptParser.For, 0); }
		public TerminalNode In() { return getToken(JavaScriptParser.In, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public VariableDeclarationListContext variableDeclarationList() {
			return getRuleContext(VariableDeclarationListContext.class,0);
		}
		public ForInStatementContext(IterationStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterForInStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitForInStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitForInStatement(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ForOfStatementContext extends IterationStatementContext {
		public TerminalNode For() { return getToken(JavaScriptParser.For, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public VariableDeclarationListContext variableDeclarationList() {
			return getRuleContext(VariableDeclarationListContext.class,0);
		}
		public TerminalNode Await() { return getToken(JavaScriptParser.Await, 0); }
		public ForOfStatementContext(IterationStatementContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterForOfStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitForOfStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitForOfStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final IterationStatementContext iterationStatement() throws RecognitionException {
		IterationStatementContext _localctx = new IterationStatementContext(_ctx, getState());
		enterRule(_localctx, 42, RULE_iterationStatement);
		int _la;
		try {
			setState(365);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,28,_ctx) ) {
			case 1:
				_localctx = new DoStatementContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(309);
				match(Do);
				setState(310);
				statement();
				setState(311);
				match(While);
				setState(312);
				match(OpenParen);
				setState(313);
				expressionSequence();
				setState(314);
				match(CloseParen);
				setState(315);
				eos();
				}
				break;
			case 2:
				_localctx = new WhileStatementContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(317);
				match(While);
				setState(318);
				match(OpenParen);
				setState(319);
				expressionSequence();
				setState(320);
				match(CloseParen);
				setState(321);
				statement();
				}
				break;
			case 3:
				_localctx = new ForStatementContext(_localctx);
				enterOuterAlt(_localctx, 3);
				{
				setState(323);
				match(For);
				setState(324);
				match(OpenParen);
				setState(327);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,22,_ctx) ) {
				case 1:
					{
					setState(325);
					expressionSequence();
					}
					break;
				case 2:
					{
					setState(326);
					variableDeclarationList();
					}
					break;
				}
				setState(329);
				match(SemiColon);
				setState(331);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << RegularExpressionLiteral) | (1L << OpenBracket) | (1L << OpenParen) | (1L << OpenBrace) | (1L << PlusPlus) | (1L << MinusMinus) | (1L << Plus) | (1L << Minus) | (1L << BitNot) | (1L << Not) | (1L << NullLiteral) | (1L << BooleanLiteral) | (1L << DecimalLiteral) | (1L << HexIntegerLiteral) | (1L << OctalIntegerLiteral))) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & ((1L << (OctalIntegerLiteral2 - 64)) | (1L << (BinaryIntegerLiteral - 64)) | (1L << (BigHexIntegerLiteral - 64)) | (1L << (BigOctalIntegerLiteral - 64)) | (1L << (BigBinaryIntegerLiteral - 64)) | (1L << (BigDecimalIntegerLiteral - 64)) | (1L << (Typeof - 64)) | (1L << (New - 64)) | (1L << (Void - 64)) | (1L << (Function - 64)) | (1L << (This - 64)) | (1L << (Delete - 64)) | (1L << (Class - 64)) | (1L << (Super - 64)) | (1L << (Import - 64)) | (1L << (Async - 64)) | (1L << (Await - 64)) | (1L << (NonStrictLet - 64)) | (1L << (Yield - 64)) | (1L << (Identifier - 64)) | (1L << (StringLiteral - 64)) | (1L << (TemplateStringLiteral - 64)))) != 0)) {
					{
					setState(330);
					expressionSequence();
					}
				}

				setState(333);
				match(SemiColon);
				setState(335);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << RegularExpressionLiteral) | (1L << OpenBracket) | (1L << OpenParen) | (1L << OpenBrace) | (1L << PlusPlus) | (1L << MinusMinus) | (1L << Plus) | (1L << Minus) | (1L << BitNot) | (1L << Not) | (1L << NullLiteral) | (1L << BooleanLiteral) | (1L << DecimalLiteral) | (1L << HexIntegerLiteral) | (1L << OctalIntegerLiteral))) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & ((1L << (OctalIntegerLiteral2 - 64)) | (1L << (BinaryIntegerLiteral - 64)) | (1L << (BigHexIntegerLiteral - 64)) | (1L << (BigOctalIntegerLiteral - 64)) | (1L << (BigBinaryIntegerLiteral - 64)) | (1L << (BigDecimalIntegerLiteral - 64)) | (1L << (Typeof - 64)) | (1L << (New - 64)) | (1L << (Void - 64)) | (1L << (Function - 64)) | (1L << (This - 64)) | (1L << (Delete - 64)) | (1L << (Class - 64)) | (1L << (Super - 64)) | (1L << (Import - 64)) | (1L << (Async - 64)) | (1L << (Await - 64)) | (1L << (NonStrictLet - 64)) | (1L << (Yield - 64)) | (1L << (Identifier - 64)) | (1L << (StringLiteral - 64)) | (1L << (TemplateStringLiteral - 64)))) != 0)) {
					{
					setState(334);
					expressionSequence();
					}
				}

				setState(337);
				match(CloseParen);
				setState(338);
				statement();
				}
				break;
			case 4:
				_localctx = new ForInStatementContext(_localctx);
				enterOuterAlt(_localctx, 4);
				{
				setState(339);
				match(For);
				setState(340);
				match(OpenParen);
				setState(343);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,25,_ctx) ) {
				case 1:
					{
					setState(341);
					singleExpression(0);
					}
					break;
				case 2:
					{
					setState(342);
					variableDeclarationList();
					}
					break;
				}
				setState(345);
				match(In);
				setState(346);
				expressionSequence();
				setState(347);
				match(CloseParen);
				setState(348);
				statement();
				}
				break;
			case 5:
				_localctx = new ForOfStatementContext(_localctx);
				enterOuterAlt(_localctx, 5);
				{
				setState(350);
				match(For);
				setState(352);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Await) {
					{
					setState(351);
					match(Await);
					}
				}

				setState(354);
				match(OpenParen);
				setState(357);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,27,_ctx) ) {
				case 1:
					{
					setState(355);
					singleExpression(0);
					}
					break;
				case 2:
					{
					setState(356);
					variableDeclarationList();
					}
					break;
				}
				setState(359);
				identifier();
				setState(360);
				if (!(this.p("of"))) throw new FailedPredicateException(this, "this.p(\"of\")");
				setState(361);
				expressionSequence();
				setState(362);
				match(CloseParen);
				setState(363);
				statement();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class VarModifierContext extends ParserRuleContext {
		public TerminalNode Var() { return getToken(JavaScriptParser.Var, 0); }
		public LetContext let() {
			return getRuleContext(LetContext.class,0);
		}
		public TerminalNode Const() { return getToken(JavaScriptParser.Const, 0); }
		public VarModifierContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_varModifier; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterVarModifier(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitVarModifier(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitVarModifier(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VarModifierContext varModifier() throws RecognitionException {
		VarModifierContext _localctx = new VarModifierContext(_ctx, getState());
		enterRule(_localctx, 44, RULE_varModifier);
		try {
			setState(370);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Var:
				enterOuterAlt(_localctx, 1);
				{
				setState(367);
				match(Var);
				}
				break;
			case StrictLet:
			case NonStrictLet:
				enterOuterAlt(_localctx, 2);
				{
				setState(368);
				let();
				}
				break;
			case Const:
				enterOuterAlt(_localctx, 3);
				{
				setState(369);
				match(Const);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ContinueStatementContext extends ParserRuleContext {
		public TerminalNode Continue() { return getToken(JavaScriptParser.Continue, 0); }
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public ContinueStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_continueStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterContinueStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitContinueStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitContinueStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ContinueStatementContext continueStatement() throws RecognitionException {
		ContinueStatementContext _localctx = new ContinueStatementContext(_ctx, getState());
		enterRule(_localctx, 46, RULE_continueStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(372);
			match(Continue);
			setState(375);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,30,_ctx) ) {
			case 1:
				{
				setState(373);
				if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
				setState(374);
				identifier();
				}
				break;
			}
			setState(377);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class BreakStatementContext extends ParserRuleContext {
		public TerminalNode Break() { return getToken(JavaScriptParser.Break, 0); }
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public BreakStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_breakStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBreakStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBreakStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBreakStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final BreakStatementContext breakStatement() throws RecognitionException {
		BreakStatementContext _localctx = new BreakStatementContext(_ctx, getState());
		enterRule(_localctx, 48, RULE_breakStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(379);
			match(Break);
			setState(382);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,31,_ctx) ) {
			case 1:
				{
				setState(380);
				if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
				setState(381);
				identifier();
				}
				break;
			}
			setState(384);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ReturnStatementContext extends ParserRuleContext {
		public TerminalNode Return() { return getToken(JavaScriptParser.Return, 0); }
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public ReturnStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_returnStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterReturnStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitReturnStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitReturnStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ReturnStatementContext returnStatement() throws RecognitionException {
		ReturnStatementContext _localctx = new ReturnStatementContext(_ctx, getState());
		enterRule(_localctx, 50, RULE_returnStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(386);
			match(Return);
			setState(389);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,32,_ctx) ) {
			case 1:
				{
				setState(387);
				if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
				setState(388);
				expressionSequence();
				}
				break;
			}
			setState(391);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class YieldStatementContext extends ParserRuleContext {
		public TerminalNode Yield() { return getToken(JavaScriptParser.Yield, 0); }
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public YieldStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_yieldStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterYieldStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitYieldStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitYieldStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final YieldStatementContext yieldStatement() throws RecognitionException {
		YieldStatementContext _localctx = new YieldStatementContext(_ctx, getState());
		enterRule(_localctx, 52, RULE_yieldStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(393);
			match(Yield);
			setState(396);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,33,_ctx) ) {
			case 1:
				{
				setState(394);
				if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
				setState(395);
				expressionSequence();
				}
				break;
			}
			setState(398);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class WithStatementContext extends ParserRuleContext {
		public TerminalNode With() { return getToken(JavaScriptParser.With, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public WithStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_withStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterWithStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitWithStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitWithStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final WithStatementContext withStatement() throws RecognitionException {
		WithStatementContext _localctx = new WithStatementContext(_ctx, getState());
		enterRule(_localctx, 54, RULE_withStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(400);
			match(With);
			setState(401);
			match(OpenParen);
			setState(402);
			expressionSequence();
			setState(403);
			match(CloseParen);
			setState(404);
			statement();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SwitchStatementContext extends ParserRuleContext {
		public TerminalNode Switch() { return getToken(JavaScriptParser.Switch, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public CaseBlockContext caseBlock() {
			return getRuleContext(CaseBlockContext.class,0);
		}
		public SwitchStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_switchStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterSwitchStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitSwitchStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitSwitchStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SwitchStatementContext switchStatement() throws RecognitionException {
		SwitchStatementContext _localctx = new SwitchStatementContext(_ctx, getState());
		enterRule(_localctx, 56, RULE_switchStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(406);
			match(Switch);
			setState(407);
			match(OpenParen);
			setState(408);
			expressionSequence();
			setState(409);
			match(CloseParen);
			setState(410);
			caseBlock();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class CaseBlockContext extends ParserRuleContext {
		public List<CaseClausesContext> caseClauses() {
			return getRuleContexts(CaseClausesContext.class);
		}
		public CaseClausesContext caseClauses(int i) {
			return getRuleContext(CaseClausesContext.class,i);
		}
		public DefaultClauseContext defaultClause() {
			return getRuleContext(DefaultClauseContext.class,0);
		}
		public CaseBlockContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_caseBlock; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterCaseBlock(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitCaseBlock(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitCaseBlock(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CaseBlockContext caseBlock() throws RecognitionException {
		CaseBlockContext _localctx = new CaseBlockContext(_ctx, getState());
		enterRule(_localctx, 58, RULE_caseBlock);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(412);
			match(OpenBrace);
			setState(414);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Case) {
				{
				setState(413);
				caseClauses();
				}
			}

			setState(420);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Default) {
				{
				setState(416);
				defaultClause();
				setState(418);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Case) {
					{
					setState(417);
					caseClauses();
					}
				}

				}
			}

			setState(422);
			match(CloseBrace);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class CaseClausesContext extends ParserRuleContext {
		public List<CaseClauseContext> caseClause() {
			return getRuleContexts(CaseClauseContext.class);
		}
		public CaseClauseContext caseClause(int i) {
			return getRuleContext(CaseClauseContext.class,i);
		}
		public CaseClausesContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_caseClauses; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterCaseClauses(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitCaseClauses(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitCaseClauses(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CaseClausesContext caseClauses() throws RecognitionException {
		CaseClausesContext _localctx = new CaseClausesContext(_ctx, getState());
		enterRule(_localctx, 60, RULE_caseClauses);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(425); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(424);
				caseClause();
				}
				}
				setState(427); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( _la==Case );
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class CaseClauseContext extends ParserRuleContext {
		public TerminalNode Case() { return getToken(JavaScriptParser.Case, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public StatementListContext statementList() {
			return getRuleContext(StatementListContext.class,0);
		}
		public CaseClauseContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_caseClause; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterCaseClause(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitCaseClause(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitCaseClause(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CaseClauseContext caseClause() throws RecognitionException {
		CaseClauseContext _localctx = new CaseClauseContext(_ctx, getState());
		enterRule(_localctx, 62, RULE_caseClause);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(429);
			match(Case);
			setState(430);
			expressionSequence();
			setState(431);
			match(Colon);
			setState(433);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,38,_ctx) ) {
			case 1:
				{
				setState(432);
				statementList();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DefaultClauseContext extends ParserRuleContext {
		public TerminalNode Default() { return getToken(JavaScriptParser.Default, 0); }
		public StatementListContext statementList() {
			return getRuleContext(StatementListContext.class,0);
		}
		public DefaultClauseContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_defaultClause; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterDefaultClause(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitDefaultClause(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitDefaultClause(this);
			else return visitor.visitChildren(this);
		}
	}

	public final DefaultClauseContext defaultClause() throws RecognitionException {
		DefaultClauseContext _localctx = new DefaultClauseContext(_ctx, getState());
		enterRule(_localctx, 64, RULE_defaultClause);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(435);
			match(Default);
			setState(436);
			match(Colon);
			setState(438);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,39,_ctx) ) {
			case 1:
				{
				setState(437);
				statementList();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LabelledStatementContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public LabelledStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_labelledStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLabelledStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLabelledStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLabelledStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LabelledStatementContext labelledStatement() throws RecognitionException {
		LabelledStatementContext _localctx = new LabelledStatementContext(_ctx, getState());
		enterRule(_localctx, 66, RULE_labelledStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(440);
			identifier();
			setState(441);
			match(Colon);
			setState(442);
			statement();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ThrowStatementContext extends ParserRuleContext {
		public TerminalNode Throw() { return getToken(JavaScriptParser.Throw, 0); }
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public ThrowStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_throwStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterThrowStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitThrowStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitThrowStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ThrowStatementContext throwStatement() throws RecognitionException {
		ThrowStatementContext _localctx = new ThrowStatementContext(_ctx, getState());
		enterRule(_localctx, 68, RULE_throwStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(444);
			match(Throw);
			setState(445);
			if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
			setState(446);
			expressionSequence();
			setState(447);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class TryStatementContext extends ParserRuleContext {
		public TerminalNode Try() { return getToken(JavaScriptParser.Try, 0); }
		public BlockContext block() {
			return getRuleContext(BlockContext.class,0);
		}
		public CatchProductionContext catchProduction() {
			return getRuleContext(CatchProductionContext.class,0);
		}
		public FinallyProductionContext finallyProduction() {
			return getRuleContext(FinallyProductionContext.class,0);
		}
		public TryStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_tryStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterTryStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitTryStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitTryStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final TryStatementContext tryStatement() throws RecognitionException {
		TryStatementContext _localctx = new TryStatementContext(_ctx, getState());
		enterRule(_localctx, 70, RULE_tryStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(449);
			match(Try);
			setState(450);
			block();
			setState(456);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Catch:
				{
				setState(451);
				catchProduction();
				setState(453);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,40,_ctx) ) {
				case 1:
					{
					setState(452);
					finallyProduction();
					}
					break;
				}
				}
				break;
			case Finally:
				{
				setState(455);
				finallyProduction();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class CatchProductionContext extends ParserRuleContext {
		public TerminalNode Catch() { return getToken(JavaScriptParser.Catch, 0); }
		public BlockContext block() {
			return getRuleContext(BlockContext.class,0);
		}
		public AssignableContext assignable() {
			return getRuleContext(AssignableContext.class,0);
		}
		public CatchProductionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_catchProduction; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterCatchProduction(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitCatchProduction(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitCatchProduction(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CatchProductionContext catchProduction() throws RecognitionException {
		CatchProductionContext _localctx = new CatchProductionContext(_ctx, getState());
		enterRule(_localctx, 72, RULE_catchProduction);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(458);
			match(Catch);
			setState(464);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==OpenParen) {
				{
				setState(459);
				match(OpenParen);
				setState(461);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==OpenBracket || _la==OpenBrace || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(460);
					assignable();
					}
				}

				setState(463);
				match(CloseParen);
				}
			}

			setState(466);
			block();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FinallyProductionContext extends ParserRuleContext {
		public TerminalNode Finally() { return getToken(JavaScriptParser.Finally, 0); }
		public BlockContext block() {
			return getRuleContext(BlockContext.class,0);
		}
		public FinallyProductionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_finallyProduction; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFinallyProduction(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFinallyProduction(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFinallyProduction(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FinallyProductionContext finallyProduction() throws RecognitionException {
		FinallyProductionContext _localctx = new FinallyProductionContext(_ctx, getState());
		enterRule(_localctx, 74, RULE_finallyProduction);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(468);
			match(Finally);
			setState(469);
			block();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DebuggerStatementContext extends ParserRuleContext {
		public TerminalNode Debugger() { return getToken(JavaScriptParser.Debugger, 0); }
		public EosContext eos() {
			return getRuleContext(EosContext.class,0);
		}
		public DebuggerStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_debuggerStatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterDebuggerStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitDebuggerStatement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitDebuggerStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final DebuggerStatementContext debuggerStatement() throws RecognitionException {
		DebuggerStatementContext _localctx = new DebuggerStatementContext(_ctx, getState());
		enterRule(_localctx, 76, RULE_debuggerStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(471);
			match(Debugger);
			setState(472);
			eos();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FunctionDeclarationContext extends ParserRuleContext {
		public TerminalNode Function() { return getToken(JavaScriptParser.Function, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public TerminalNode Async() { return getToken(JavaScriptParser.Async, 0); }
		public FormalParameterListContext formalParameterList() {
			return getRuleContext(FormalParameterListContext.class,0);
		}
		public FunctionDeclarationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_functionDeclaration; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFunctionDeclaration(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFunctionDeclaration(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFunctionDeclaration(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FunctionDeclarationContext functionDeclaration() throws RecognitionException {
		FunctionDeclarationContext _localctx = new FunctionDeclarationContext(_ctx, getState());
		enterRule(_localctx, 78, RULE_functionDeclaration);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(475);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Async) {
				{
				setState(474);
				match(Async);
				}
			}

			setState(477);
			match(Function);
			setState(479);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Multiply) {
				{
				setState(478);
				match(Multiply);
				}
			}

			setState(481);
			identifier();
			setState(482);
			match(OpenParen);
			setState(484);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << OpenBracket) | (1L << OpenBrace) | (1L << Ellipsis))) != 0) || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
				{
				setState(483);
				formalParameterList();
				}
			}

			setState(486);
			match(CloseParen);
			setState(487);
			match(OpenBrace);
			setState(488);
			functionBody();
			setState(489);
			match(CloseBrace);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ClassDeclarationContext extends ParserRuleContext {
		public TerminalNode Class() { return getToken(JavaScriptParser.Class, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public ClassTailContext classTail() {
			return getRuleContext(ClassTailContext.class,0);
		}
		public ClassDeclarationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_classDeclaration; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterClassDeclaration(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitClassDeclaration(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitClassDeclaration(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ClassDeclarationContext classDeclaration() throws RecognitionException {
		ClassDeclarationContext _localctx = new ClassDeclarationContext(_ctx, getState());
		enterRule(_localctx, 80, RULE_classDeclaration);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(491);
			match(Class);
			setState(492);
			identifier();
			setState(493);
			classTail();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ClassTailContext extends ParserRuleContext {
		public TerminalNode Extends() { return getToken(JavaScriptParser.Extends, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public List<ClassElementContext> classElement() {
			return getRuleContexts(ClassElementContext.class);
		}
		public ClassElementContext classElement(int i) {
			return getRuleContext(ClassElementContext.class,i);
		}
		public ClassTailContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_classTail; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterClassTail(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitClassTail(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitClassTail(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ClassTailContext classTail() throws RecognitionException {
		ClassTailContext _localctx = new ClassTailContext(_ctx, getState());
		enterRule(_localctx, 82, RULE_classTail);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(497);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Extends) {
				{
				setState(495);
				match(Extends);
				setState(496);
				singleExpression(0);
				}
			}

			setState(499);
			match(OpenBrace);
			setState(503);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,48,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(500);
					classElement();
					}
					} 
				}
				setState(505);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,48,_ctx);
			}
			setState(506);
			match(CloseBrace);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ClassElementContext extends ParserRuleContext {
		public MethodDefinitionContext methodDefinition() {
			return getRuleContext(MethodDefinitionContext.class,0);
		}
		public AssignableContext assignable() {
			return getRuleContext(AssignableContext.class,0);
		}
		public ObjectLiteralContext objectLiteral() {
			return getRuleContext(ObjectLiteralContext.class,0);
		}
		public List<TerminalNode> Static() { return getTokens(JavaScriptParser.Static); }
		public TerminalNode Static(int i) {
			return getToken(JavaScriptParser.Static, i);
		}
		public List<IdentifierContext> identifier() {
			return getRuleContexts(IdentifierContext.class);
		}
		public IdentifierContext identifier(int i) {
			return getRuleContext(IdentifierContext.class,i);
		}
		public List<TerminalNode> Async() { return getTokens(JavaScriptParser.Async); }
		public TerminalNode Async(int i) {
			return getToken(JavaScriptParser.Async, i);
		}
		public EmptyStatementContext emptyStatement() {
			return getRuleContext(EmptyStatementContext.class,0);
		}
		public PropertyNameContext propertyName() {
			return getRuleContext(PropertyNameContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public ClassElementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_classElement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterClassElement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitClassElement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitClassElement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ClassElementContext classElement() throws RecognitionException {
		ClassElementContext _localctx = new ClassElementContext(_ctx, getState());
		enterRule(_localctx, 84, RULE_classElement);
		int _la;
		try {
			int _alt;
			setState(533);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,53,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(514);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,50,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						setState(512);
						_errHandler.sync(this);
						switch ( getInterpreter().adaptivePredict(_input,49,_ctx) ) {
						case 1:
							{
							setState(508);
							match(Static);
							}
							break;
						case 2:
							{
							setState(509);
							if (!(this.n("static"))) throw new FailedPredicateException(this, "this.n(\"static\")");
							setState(510);
							identifier();
							}
							break;
						case 3:
							{
							setState(511);
							match(Async);
							}
							break;
						}
						} 
					}
					setState(516);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,50,_ctx);
				}
				setState(523);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,51,_ctx) ) {
				case 1:
					{
					setState(517);
					methodDefinition();
					}
					break;
				case 2:
					{
					setState(518);
					assignable();
					setState(519);
					match(Assign);
					setState(520);
					objectLiteral();
					setState(521);
					match(SemiColon);
					}
					break;
				}
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(525);
				emptyStatement();
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				setState(527);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Hashtag) {
					{
					setState(526);
					match(Hashtag);
					}
				}

				setState(529);
				propertyName();
				setState(530);
				match(Assign);
				setState(531);
				singleExpression(0);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class MethodDefinitionContext extends ParserRuleContext {
		public PropertyNameContext propertyName() {
			return getRuleContext(PropertyNameContext.class,0);
		}
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public FormalParameterListContext formalParameterList() {
			return getRuleContext(FormalParameterListContext.class,0);
		}
		public GetterContext getter() {
			return getRuleContext(GetterContext.class,0);
		}
		public SetterContext setter() {
			return getRuleContext(SetterContext.class,0);
		}
		public MethodDefinitionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_methodDefinition; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterMethodDefinition(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitMethodDefinition(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitMethodDefinition(this);
			else return visitor.visitChildren(this);
		}
	}

	public final MethodDefinitionContext methodDefinition() throws RecognitionException {
		MethodDefinitionContext _localctx = new MethodDefinitionContext(_ctx, getState());
		enterRule(_localctx, 86, RULE_methodDefinition);
		int _la;
		try {
			setState(580);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,62,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(536);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Multiply) {
					{
					setState(535);
					match(Multiply);
					}
				}

				setState(539);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Hashtag) {
					{
					setState(538);
					match(Hashtag);
					}
				}

				setState(541);
				propertyName();
				setState(542);
				match(OpenParen);
				setState(544);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << OpenBracket) | (1L << OpenBrace) | (1L << Ellipsis))) != 0) || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(543);
					formalParameterList();
					}
				}

				setState(546);
				match(CloseParen);
				setState(547);
				match(OpenBrace);
				setState(548);
				functionBody();
				setState(549);
				match(CloseBrace);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(552);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,57,_ctx) ) {
				case 1:
					{
					setState(551);
					match(Multiply);
					}
					break;
				}
				setState(555);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,58,_ctx) ) {
				case 1:
					{
					setState(554);
					match(Hashtag);
					}
					break;
				}
				setState(557);
				getter();
				setState(558);
				match(OpenParen);
				setState(559);
				match(CloseParen);
				setState(560);
				match(OpenBrace);
				setState(561);
				functionBody();
				setState(562);
				match(CloseBrace);
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				setState(565);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,59,_ctx) ) {
				case 1:
					{
					setState(564);
					match(Multiply);
					}
					break;
				}
				setState(568);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,60,_ctx) ) {
				case 1:
					{
					setState(567);
					match(Hashtag);
					}
					break;
				}
				setState(570);
				setter();
				setState(571);
				match(OpenParen);
				setState(573);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << OpenBracket) | (1L << OpenBrace) | (1L << Ellipsis))) != 0) || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(572);
					formalParameterList();
					}
				}

				setState(575);
				match(CloseParen);
				setState(576);
				match(OpenBrace);
				setState(577);
				functionBody();
				setState(578);
				match(CloseBrace);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FormalParameterListContext extends ParserRuleContext {
		public List<FormalParameterArgContext> formalParameterArg() {
			return getRuleContexts(FormalParameterArgContext.class);
		}
		public FormalParameterArgContext formalParameterArg(int i) {
			return getRuleContext(FormalParameterArgContext.class,i);
		}
		public LastFormalParameterArgContext lastFormalParameterArg() {
			return getRuleContext(LastFormalParameterArgContext.class,0);
		}
		public FormalParameterListContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_formalParameterList; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFormalParameterList(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFormalParameterList(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFormalParameterList(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FormalParameterListContext formalParameterList() throws RecognitionException {
		FormalParameterListContext _localctx = new FormalParameterListContext(_ctx, getState());
		enterRule(_localctx, 88, RULE_formalParameterList);
		int _la;
		try {
			int _alt;
			setState(595);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case OpenBracket:
			case OpenBrace:
			case Async:
			case NonStrictLet:
			case Identifier:
				enterOuterAlt(_localctx, 1);
				{
				setState(582);
				formalParameterArg();
				setState(587);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,63,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(583);
						match(Comma);
						setState(584);
						formalParameterArg();
						}
						} 
					}
					setState(589);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,63,_ctx);
				}
				setState(592);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Comma) {
					{
					setState(590);
					match(Comma);
					setState(591);
					lastFormalParameterArg();
					}
				}

				}
				break;
			case Ellipsis:
				enterOuterAlt(_localctx, 2);
				{
				setState(594);
				lastFormalParameterArg();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FormalParameterArgContext extends ParserRuleContext {
		public AssignableContext assignable() {
			return getRuleContext(AssignableContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public FormalParameterArgContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_formalParameterArg; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFormalParameterArg(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFormalParameterArg(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFormalParameterArg(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FormalParameterArgContext formalParameterArg() throws RecognitionException {
		FormalParameterArgContext _localctx = new FormalParameterArgContext(_ctx, getState());
		enterRule(_localctx, 90, RULE_formalParameterArg);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(597);
			assignable();
			setState(600);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Assign) {
				{
				setState(598);
				match(Assign);
				setState(599);
				singleExpression(0);
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LastFormalParameterArgContext extends ParserRuleContext {
		public TerminalNode Ellipsis() { return getToken(JavaScriptParser.Ellipsis, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public LastFormalParameterArgContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_lastFormalParameterArg; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLastFormalParameterArg(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLastFormalParameterArg(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLastFormalParameterArg(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LastFormalParameterArgContext lastFormalParameterArg() throws RecognitionException {
		LastFormalParameterArgContext _localctx = new LastFormalParameterArgContext(_ctx, getState());
		enterRule(_localctx, 92, RULE_lastFormalParameterArg);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(602);
			match(Ellipsis);
			setState(603);
			singleExpression(0);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FunctionBodyContext extends ParserRuleContext {
		public SourceElementsContext sourceElements() {
			return getRuleContext(SourceElementsContext.class,0);
		}
		public FunctionBodyContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_functionBody; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFunctionBody(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFunctionBody(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFunctionBody(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FunctionBodyContext functionBody() throws RecognitionException {
		FunctionBodyContext _localctx = new FunctionBodyContext(_ctx, getState());
		enterRule(_localctx, 94, RULE_functionBody);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(606);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,67,_ctx) ) {
			case 1:
				{
				setState(605);
				sourceElements();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SourceElementsContext extends ParserRuleContext {
		public List<SourceElementContext> sourceElement() {
			return getRuleContexts(SourceElementContext.class);
		}
		public SourceElementContext sourceElement(int i) {
			return getRuleContext(SourceElementContext.class,i);
		}
		public SourceElementsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sourceElements; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterSourceElements(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitSourceElements(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitSourceElements(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SourceElementsContext sourceElements() throws RecognitionException {
		SourceElementsContext _localctx = new SourceElementsContext(_ctx, getState());
		enterRule(_localctx, 96, RULE_sourceElements);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(609); 
			_errHandler.sync(this);
			_alt = 1;
			do {
				switch (_alt) {
				case 1:
					{
					{
					setState(608);
					sourceElement();
					}
					}
					break;
				default:
					throw new NoViableAltException(this);
				}
				setState(611); 
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,68,_ctx);
			} while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER );
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArrayLiteralContext extends ParserRuleContext {
		public ElementListContext elementList() {
			return getRuleContext(ElementListContext.class,0);
		}
		public ArrayLiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arrayLiteral; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArrayLiteral(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArrayLiteral(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArrayLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArrayLiteralContext arrayLiteral() throws RecognitionException {
		ArrayLiteralContext _localctx = new ArrayLiteralContext(_ctx, getState());
		enterRule(_localctx, 98, RULE_arrayLiteral);
		try {
			enterOuterAlt(_localctx, 1);
			{
			{
			setState(613);
			match(OpenBracket);
			setState(614);
			elementList();
			setState(615);
			match(CloseBracket);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ElementListContext extends ParserRuleContext {
		public List<ArrayElementContext> arrayElement() {
			return getRuleContexts(ArrayElementContext.class);
		}
		public ArrayElementContext arrayElement(int i) {
			return getRuleContext(ArrayElementContext.class,i);
		}
		public ElementListContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_elementList; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterElementList(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitElementList(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitElementList(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ElementListContext elementList() throws RecognitionException {
		ElementListContext _localctx = new ElementListContext(_ctx, getState());
		enterRule(_localctx, 100, RULE_elementList);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(620);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,69,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(617);
					match(Comma);
					}
					} 
				}
				setState(622);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,69,_ctx);
			}
			setState(624);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << RegularExpressionLiteral) | (1L << OpenBracket) | (1L << OpenParen) | (1L << OpenBrace) | (1L << Ellipsis) | (1L << PlusPlus) | (1L << MinusMinus) | (1L << Plus) | (1L << Minus) | (1L << BitNot) | (1L << Not) | (1L << NullLiteral) | (1L << BooleanLiteral) | (1L << DecimalLiteral) | (1L << HexIntegerLiteral) | (1L << OctalIntegerLiteral))) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & ((1L << (OctalIntegerLiteral2 - 64)) | (1L << (BinaryIntegerLiteral - 64)) | (1L << (BigHexIntegerLiteral - 64)) | (1L << (BigOctalIntegerLiteral - 64)) | (1L << (BigBinaryIntegerLiteral - 64)) | (1L << (BigDecimalIntegerLiteral - 64)) | (1L << (Typeof - 64)) | (1L << (New - 64)) | (1L << (Void - 64)) | (1L << (Function - 64)) | (1L << (This - 64)) | (1L << (Delete - 64)) | (1L << (Class - 64)) | (1L << (Super - 64)) | (1L << (Import - 64)) | (1L << (Async - 64)) | (1L << (Await - 64)) | (1L << (NonStrictLet - 64)) | (1L << (Yield - 64)) | (1L << (Identifier - 64)) | (1L << (StringLiteral - 64)) | (1L << (TemplateStringLiteral - 64)))) != 0)) {
				{
				setState(623);
				arrayElement();
				}
			}

			setState(634);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,72,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(627); 
					_errHandler.sync(this);
					_la = _input.LA(1);
					do {
						{
						{
						setState(626);
						match(Comma);
						}
						}
						setState(629); 
						_errHandler.sync(this);
						_la = _input.LA(1);
					} while ( _la==Comma );
					setState(631);
					arrayElement();
					}
					} 
				}
				setState(636);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,72,_ctx);
			}
			setState(640);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==Comma) {
				{
				{
				setState(637);
				match(Comma);
				}
				}
				setState(642);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArrayElementContext extends ParserRuleContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public TerminalNode Ellipsis() { return getToken(JavaScriptParser.Ellipsis, 0); }
		public ArrayElementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arrayElement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArrayElement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArrayElement(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArrayElement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArrayElementContext arrayElement() throws RecognitionException {
		ArrayElementContext _localctx = new ArrayElementContext(_ctx, getState());
		enterRule(_localctx, 102, RULE_arrayElement);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(644);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Ellipsis) {
				{
				setState(643);
				match(Ellipsis);
				}
			}

			setState(646);
			singleExpression(0);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class PropertyAssignmentContext extends ParserRuleContext {
		public PropertyAssignmentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_propertyAssignment; }
	 
		public PropertyAssignmentContext() { }
		public void copyFrom(PropertyAssignmentContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class PropertyExpressionAssignmentContext extends PropertyAssignmentContext {
		public PropertyNameContext propertyName() {
			return getRuleContext(PropertyNameContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public PropertyExpressionAssignmentContext(PropertyAssignmentContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPropertyExpressionAssignment(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPropertyExpressionAssignment(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPropertyExpressionAssignment(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ComputedPropertyExpressionAssignmentContext extends PropertyAssignmentContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public ComputedPropertyExpressionAssignmentContext(PropertyAssignmentContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterComputedPropertyExpressionAssignment(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitComputedPropertyExpressionAssignment(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitComputedPropertyExpressionAssignment(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PropertyShorthandContext extends PropertyAssignmentContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public TerminalNode Ellipsis() { return getToken(JavaScriptParser.Ellipsis, 0); }
		public PropertyShorthandContext(PropertyAssignmentContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPropertyShorthand(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPropertyShorthand(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPropertyShorthand(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PropertySetterContext extends PropertyAssignmentContext {
		public SetterContext setter() {
			return getRuleContext(SetterContext.class,0);
		}
		public FormalParameterArgContext formalParameterArg() {
			return getRuleContext(FormalParameterArgContext.class,0);
		}
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public PropertySetterContext(PropertyAssignmentContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPropertySetter(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPropertySetter(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPropertySetter(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PropertyGetterContext extends PropertyAssignmentContext {
		public GetterContext getter() {
			return getRuleContext(GetterContext.class,0);
		}
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public PropertyGetterContext(PropertyAssignmentContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPropertyGetter(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPropertyGetter(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPropertyGetter(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class FunctionPropertyContext extends PropertyAssignmentContext {
		public PropertyNameContext propertyName() {
			return getRuleContext(PropertyNameContext.class,0);
		}
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public TerminalNode Async() { return getToken(JavaScriptParser.Async, 0); }
		public FormalParameterListContext formalParameterList() {
			return getRuleContext(FormalParameterListContext.class,0);
		}
		public FunctionPropertyContext(PropertyAssignmentContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFunctionProperty(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFunctionProperty(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFunctionProperty(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PropertyAssignmentContext propertyAssignment() throws RecognitionException {
		PropertyAssignmentContext _localctx = new PropertyAssignmentContext(_ctx, getState());
		enterRule(_localctx, 104, RULE_propertyAssignment);
		int _la;
		try {
			setState(693);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,79,_ctx) ) {
			case 1:
				_localctx = new PropertyExpressionAssignmentContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(648);
				propertyName();
				setState(649);
				match(Colon);
				setState(650);
				singleExpression(0);
				}
				break;
			case 2:
				_localctx = new ComputedPropertyExpressionAssignmentContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(652);
				match(OpenBracket);
				setState(653);
				singleExpression(0);
				setState(654);
				match(CloseBracket);
				setState(655);
				match(Colon);
				setState(656);
				singleExpression(0);
				}
				break;
			case 3:
				_localctx = new FunctionPropertyContext(_localctx);
				enterOuterAlt(_localctx, 3);
				{
				setState(659);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,75,_ctx) ) {
				case 1:
					{
					setState(658);
					match(Async);
					}
					break;
				}
				setState(662);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Multiply) {
					{
					setState(661);
					match(Multiply);
					}
				}

				setState(664);
				propertyName();
				setState(665);
				match(OpenParen);
				setState(667);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << OpenBracket) | (1L << OpenBrace) | (1L << Ellipsis))) != 0) || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(666);
					formalParameterList();
					}
				}

				setState(669);
				match(CloseParen);
				setState(670);
				match(OpenBrace);
				setState(671);
				functionBody();
				setState(672);
				match(CloseBrace);
				}
				break;
			case 4:
				_localctx = new PropertyGetterContext(_localctx);
				enterOuterAlt(_localctx, 4);
				{
				setState(674);
				getter();
				setState(675);
				match(OpenParen);
				setState(676);
				match(CloseParen);
				setState(677);
				match(OpenBrace);
				setState(678);
				functionBody();
				setState(679);
				match(CloseBrace);
				}
				break;
			case 5:
				_localctx = new PropertySetterContext(_localctx);
				enterOuterAlt(_localctx, 5);
				{
				setState(681);
				setter();
				setState(682);
				match(OpenParen);
				setState(683);
				formalParameterArg();
				setState(684);
				match(CloseParen);
				setState(685);
				match(OpenBrace);
				setState(686);
				functionBody();
				setState(687);
				match(CloseBrace);
				}
				break;
			case 6:
				_localctx = new PropertyShorthandContext(_localctx);
				enterOuterAlt(_localctx, 6);
				{
				setState(690);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Ellipsis) {
					{
					setState(689);
					match(Ellipsis);
					}
				}

				setState(692);
				singleExpression(0);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class PropertyNameContext extends ParserRuleContext {
		public IdentifierNameContext identifierName() {
			return getRuleContext(IdentifierNameContext.class,0);
		}
		public TerminalNode StringLiteral() { return getToken(JavaScriptParser.StringLiteral, 0); }
		public NumericLiteralContext numericLiteral() {
			return getRuleContext(NumericLiteralContext.class,0);
		}
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public PropertyNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_propertyName; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPropertyName(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPropertyName(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPropertyName(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PropertyNameContext propertyName() throws RecognitionException {
		PropertyNameContext _localctx = new PropertyNameContext(_ctx, getState());
		enterRule(_localctx, 106, RULE_propertyName);
		try {
			setState(702);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case NullLiteral:
			case BooleanLiteral:
			case Break:
			case Do:
			case Instanceof:
			case Typeof:
			case Case:
			case Else:
			case New:
			case Var:
			case Catch:
			case Finally:
			case Return:
			case Void:
			case Continue:
			case For:
			case Switch:
			case While:
			case Debugger:
			case Function:
			case This:
			case With:
			case Default:
			case If:
			case Throw:
			case Delete:
			case In:
			case Try:
			case As:
			case From:
			case Class:
			case Enum:
			case Extends:
			case Super:
			case Const:
			case Export:
			case Import:
			case Async:
			case Await:
			case Implements:
			case StrictLet:
			case NonStrictLet:
			case Private:
			case Public:
			case Interface:
			case Package:
			case Protected:
			case Static:
			case Yield:
			case Identifier:
				enterOuterAlt(_localctx, 1);
				{
				setState(695);
				identifierName();
				}
				break;
			case StringLiteral:
				enterOuterAlt(_localctx, 2);
				{
				setState(696);
				match(StringLiteral);
				}
				break;
			case DecimalLiteral:
			case HexIntegerLiteral:
			case OctalIntegerLiteral:
			case OctalIntegerLiteral2:
			case BinaryIntegerLiteral:
				enterOuterAlt(_localctx, 3);
				{
				setState(697);
				numericLiteral();
				}
				break;
			case OpenBracket:
				enterOuterAlt(_localctx, 4);
				{
				setState(698);
				match(OpenBracket);
				setState(699);
				singleExpression(0);
				setState(700);
				match(CloseBracket);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArgumentsContext extends ParserRuleContext {
		public List<ArgumentContext> argument() {
			return getRuleContexts(ArgumentContext.class);
		}
		public ArgumentContext argument(int i) {
			return getRuleContext(ArgumentContext.class,i);
		}
		public ArgumentsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arguments; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArguments(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArguments(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArguments(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArgumentsContext arguments() throws RecognitionException {
		ArgumentsContext _localctx = new ArgumentsContext(_ctx, getState());
		enterRule(_localctx, 108, RULE_arguments);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(704);
			match(OpenParen);
			setState(716);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << RegularExpressionLiteral) | (1L << OpenBracket) | (1L << OpenParen) | (1L << OpenBrace) | (1L << Ellipsis) | (1L << PlusPlus) | (1L << MinusMinus) | (1L << Plus) | (1L << Minus) | (1L << BitNot) | (1L << Not) | (1L << NullLiteral) | (1L << BooleanLiteral) | (1L << DecimalLiteral) | (1L << HexIntegerLiteral) | (1L << OctalIntegerLiteral))) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & ((1L << (OctalIntegerLiteral2 - 64)) | (1L << (BinaryIntegerLiteral - 64)) | (1L << (BigHexIntegerLiteral - 64)) | (1L << (BigOctalIntegerLiteral - 64)) | (1L << (BigBinaryIntegerLiteral - 64)) | (1L << (BigDecimalIntegerLiteral - 64)) | (1L << (Typeof - 64)) | (1L << (New - 64)) | (1L << (Void - 64)) | (1L << (Function - 64)) | (1L << (This - 64)) | (1L << (Delete - 64)) | (1L << (Class - 64)) | (1L << (Super - 64)) | (1L << (Import - 64)) | (1L << (Async - 64)) | (1L << (Await - 64)) | (1L << (NonStrictLet - 64)) | (1L << (Yield - 64)) | (1L << (Identifier - 64)) | (1L << (StringLiteral - 64)) | (1L << (TemplateStringLiteral - 64)))) != 0)) {
				{
				setState(705);
				argument();
				setState(710);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,81,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(706);
						match(Comma);
						setState(707);
						argument();
						}
						} 
					}
					setState(712);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,81,_ctx);
				}
				setState(714);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Comma) {
					{
					setState(713);
					match(Comma);
					}
				}

				}
			}

			setState(718);
			match(CloseParen);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArgumentContext extends ParserRuleContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode Ellipsis() { return getToken(JavaScriptParser.Ellipsis, 0); }
		public ArgumentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_argument; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArgument(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArgument(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArgument(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArgumentContext argument() throws RecognitionException {
		ArgumentContext _localctx = new ArgumentContext(_ctx, getState());
		enterRule(_localctx, 110, RULE_argument);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(721);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Ellipsis) {
				{
				setState(720);
				match(Ellipsis);
				}
			}

			setState(725);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,85,_ctx) ) {
			case 1:
				{
				setState(723);
				singleExpression(0);
				}
				break;
			case 2:
				{
				setState(724);
				identifier();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ExpressionSequenceContext extends ParserRuleContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public ExpressionSequenceContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_expressionSequence; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterExpressionSequence(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitExpressionSequence(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitExpressionSequence(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ExpressionSequenceContext expressionSequence() throws RecognitionException {
		ExpressionSequenceContext _localctx = new ExpressionSequenceContext(_ctx, getState());
		enterRule(_localctx, 112, RULE_expressionSequence);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(727);
			singleExpression(0);
			setState(732);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,86,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(728);
					match(Comma);
					setState(729);
					singleExpression(0);
					}
					} 
				}
				setState(734);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,86,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SingleExpressionContext extends ParserRuleContext {
		public SingleExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_singleExpression; }
	 
		public SingleExpressionContext() { }
		public void copyFrom(SingleExpressionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class TemplateStringExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public TerminalNode TemplateStringLiteral() { return getToken(JavaScriptParser.TemplateStringLiteral, 0); }
		public TemplateStringExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterTemplateStringExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitTemplateStringExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitTemplateStringExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class TernaryExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public TernaryExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterTernaryExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitTernaryExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitTernaryExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class LogicalAndExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public LogicalAndExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLogicalAndExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLogicalAndExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLogicalAndExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PowerExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public PowerExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPowerExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPowerExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPowerExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PreIncrementExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public PreIncrementExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPreIncrementExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPreIncrementExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPreIncrementExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ObjectLiteralExpressionContext extends SingleExpressionContext {
		public ObjectLiteralContext objectLiteral() {
			return getRuleContext(ObjectLiteralContext.class,0);
		}
		public ObjectLiteralExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterObjectLiteralExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitObjectLiteralExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitObjectLiteralExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class MetaExpressionContext extends SingleExpressionContext {
		public TerminalNode New() { return getToken(JavaScriptParser.New, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public MetaExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterMetaExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitMetaExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitMetaExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class InExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public TerminalNode In() { return getToken(JavaScriptParser.In, 0); }
		public InExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterInExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitInExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitInExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class LogicalOrExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public LogicalOrExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLogicalOrExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLogicalOrExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLogicalOrExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class NotExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public NotExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterNotExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitNotExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitNotExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PreDecreaseExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public PreDecreaseExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPreDecreaseExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPreDecreaseExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPreDecreaseExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ArgumentsExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public ArgumentsContext arguments() {
			return getRuleContext(ArgumentsContext.class,0);
		}
		public ArgumentsExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArgumentsExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArgumentsExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArgumentsExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class AwaitExpressionContext extends SingleExpressionContext {
		public TerminalNode Await() { return getToken(JavaScriptParser.Await, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public AwaitExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAwaitExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAwaitExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAwaitExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ThisExpressionContext extends SingleExpressionContext {
		public TerminalNode This() { return getToken(JavaScriptParser.This, 0); }
		public ThisExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterThisExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitThisExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitThisExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class FunctionExpressionContext extends SingleExpressionContext {
		public AnoymousFunctionContext anoymousFunction() {
			return getRuleContext(AnoymousFunctionContext.class,0);
		}
		public FunctionExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFunctionExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFunctionExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFunctionExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class UnaryMinusExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public UnaryMinusExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterUnaryMinusExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitUnaryMinusExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitUnaryMinusExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class AssignmentExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public AssignmentExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAssignmentExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAssignmentExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAssignmentExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PostDecreaseExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public PostDecreaseExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPostDecreaseExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPostDecreaseExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPostDecreaseExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class TypeofExpressionContext extends SingleExpressionContext {
		public TerminalNode Typeof() { return getToken(JavaScriptParser.Typeof, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public TypeofExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterTypeofExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitTypeofExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitTypeofExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class InstanceofExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public TerminalNode Instanceof() { return getToken(JavaScriptParser.Instanceof, 0); }
		public InstanceofExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterInstanceofExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitInstanceofExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitInstanceofExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class UnaryPlusExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public UnaryPlusExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterUnaryPlusExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitUnaryPlusExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitUnaryPlusExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class DeleteExpressionContext extends SingleExpressionContext {
		public TerminalNode Delete() { return getToken(JavaScriptParser.Delete, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public DeleteExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterDeleteExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitDeleteExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitDeleteExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ImportExpressionContext extends SingleExpressionContext {
		public TerminalNode Import() { return getToken(JavaScriptParser.Import, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public ImportExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterImportExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitImportExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitImportExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class EqualityExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public EqualityExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterEqualityExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitEqualityExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitEqualityExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class BitXOrExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public BitXOrExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBitXOrExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBitXOrExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBitXOrExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class SuperExpressionContext extends SingleExpressionContext {
		public TerminalNode Super() { return getToken(JavaScriptParser.Super, 0); }
		public SuperExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterSuperExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitSuperExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitSuperExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class MultiplicativeExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public MultiplicativeExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterMultiplicativeExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitMultiplicativeExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitMultiplicativeExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class BitShiftExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public BitShiftExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBitShiftExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBitShiftExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBitShiftExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ParenthesizedExpressionContext extends SingleExpressionContext {
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public ParenthesizedExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterParenthesizedExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitParenthesizedExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitParenthesizedExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class AdditiveExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public AdditiveExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAdditiveExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAdditiveExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAdditiveExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class RelationalExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public RelationalExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterRelationalExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitRelationalExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitRelationalExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class PostIncrementExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public PostIncrementExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterPostIncrementExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitPostIncrementExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitPostIncrementExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class YieldExpressionContext extends SingleExpressionContext {
		public YieldStatementContext yieldStatement() {
			return getRuleContext(YieldStatementContext.class,0);
		}
		public YieldExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterYieldExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitYieldExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitYieldExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class BitNotExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public BitNotExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBitNotExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBitNotExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBitNotExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class NewExpressionContext extends SingleExpressionContext {
		public TerminalNode New() { return getToken(JavaScriptParser.New, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public ArgumentsContext arguments() {
			return getRuleContext(ArgumentsContext.class,0);
		}
		public NewExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterNewExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitNewExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitNewExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class LiteralExpressionContext extends SingleExpressionContext {
		public LiteralContext literal() {
			return getRuleContext(LiteralContext.class,0);
		}
		public LiteralExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLiteralExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLiteralExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLiteralExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ArrayLiteralExpressionContext extends SingleExpressionContext {
		public ArrayLiteralContext arrayLiteral() {
			return getRuleContext(ArrayLiteralContext.class,0);
		}
		public ArrayLiteralExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArrayLiteralExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArrayLiteralExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArrayLiteralExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class MemberDotExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public IdentifierNameContext identifierName() {
			return getRuleContext(IdentifierNameContext.class,0);
		}
		public MemberDotExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterMemberDotExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitMemberDotExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitMemberDotExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ClassExpressionContext extends SingleExpressionContext {
		public TerminalNode Class() { return getToken(JavaScriptParser.Class, 0); }
		public ClassTailContext classTail() {
			return getRuleContext(ClassTailContext.class,0);
		}
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public ClassExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterClassExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitClassExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitClassExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class MemberIndexExpressionContext extends SingleExpressionContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public ExpressionSequenceContext expressionSequence() {
			return getRuleContext(ExpressionSequenceContext.class,0);
		}
		public MemberIndexExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterMemberIndexExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitMemberIndexExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitMemberIndexExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class IdentifierExpressionContext extends SingleExpressionContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public IdentifierExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterIdentifierExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitIdentifierExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitIdentifierExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class BitAndExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public BitAndExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBitAndExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBitAndExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBitAndExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class BitOrExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public BitOrExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBitOrExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBitOrExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBitOrExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class AssignmentOperatorExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public AssignmentOperatorContext assignmentOperator() {
			return getRuleContext(AssignmentOperatorContext.class,0);
		}
		public AssignmentOperatorExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAssignmentOperatorExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAssignmentOperatorExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAssignmentOperatorExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class VoidExpressionContext extends SingleExpressionContext {
		public TerminalNode Void() { return getToken(JavaScriptParser.Void, 0); }
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public VoidExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterVoidExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitVoidExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitVoidExpression(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class CoalesceExpressionContext extends SingleExpressionContext {
		public List<SingleExpressionContext> singleExpression() {
			return getRuleContexts(SingleExpressionContext.class);
		}
		public SingleExpressionContext singleExpression(int i) {
			return getRuleContext(SingleExpressionContext.class,i);
		}
		public CoalesceExpressionContext(SingleExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterCoalesceExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitCoalesceExpression(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitCoalesceExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SingleExpressionContext singleExpression() throws RecognitionException {
		return singleExpression(0);
	}

	private SingleExpressionContext singleExpression(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		SingleExpressionContext _localctx = new SingleExpressionContext(_ctx, _parentState);
		SingleExpressionContext _prevctx = _localctx;
		int _startState = 114;
		enterRecursionRule(_localctx, 114, RULE_singleExpression, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(786);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,89,_ctx) ) {
			case 1:
				{
				_localctx = new FunctionExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(736);
				anoymousFunction();
				}
				break;
			case 2:
				{
				_localctx = new ClassExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(737);
				match(Class);
				setState(739);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(738);
					identifier();
					}
				}

				setState(741);
				classTail();
				}
				break;
			case 3:
				{
				_localctx = new NewExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(742);
				match(New);
				setState(743);
				singleExpression(0);
				setState(745);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,88,_ctx) ) {
				case 1:
					{
					setState(744);
					arguments();
					}
					break;
				}
				}
				break;
			case 4:
				{
				_localctx = new MetaExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(747);
				match(New);
				setState(748);
				match(Dot);
				setState(749);
				identifier();
				}
				break;
			case 5:
				{
				_localctx = new DeleteExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(750);
				match(Delete);
				setState(751);
				singleExpression(37);
				}
				break;
			case 6:
				{
				_localctx = new VoidExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(752);
				match(Void);
				setState(753);
				singleExpression(36);
				}
				break;
			case 7:
				{
				_localctx = new TypeofExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(754);
				match(Typeof);
				setState(755);
				singleExpression(35);
				}
				break;
			case 8:
				{
				_localctx = new PreIncrementExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(756);
				match(PlusPlus);
				setState(757);
				singleExpression(34);
				}
				break;
			case 9:
				{
				_localctx = new PreDecreaseExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(758);
				match(MinusMinus);
				setState(759);
				singleExpression(33);
				}
				break;
			case 10:
				{
				_localctx = new UnaryPlusExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(760);
				match(Plus);
				setState(761);
				singleExpression(32);
				}
				break;
			case 11:
				{
				_localctx = new UnaryMinusExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(762);
				match(Minus);
				setState(763);
				singleExpression(31);
				}
				break;
			case 12:
				{
				_localctx = new BitNotExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(764);
				match(BitNot);
				setState(765);
				singleExpression(30);
				}
				break;
			case 13:
				{
				_localctx = new NotExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(766);
				match(Not);
				setState(767);
				singleExpression(29);
				}
				break;
			case 14:
				{
				_localctx = new AwaitExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(768);
				match(Await);
				setState(769);
				singleExpression(28);
				}
				break;
			case 15:
				{
				_localctx = new ImportExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(770);
				match(Import);
				setState(771);
				match(OpenParen);
				setState(772);
				singleExpression(0);
				setState(773);
				match(CloseParen);
				}
				break;
			case 16:
				{
				_localctx = new YieldExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(775);
				yieldStatement();
				}
				break;
			case 17:
				{
				_localctx = new ThisExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(776);
				match(This);
				}
				break;
			case 18:
				{
				_localctx = new IdentifierExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(777);
				identifier();
				}
				break;
			case 19:
				{
				_localctx = new SuperExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(778);
				match(Super);
				}
				break;
			case 20:
				{
				_localctx = new LiteralExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(779);
				literal();
				}
				break;
			case 21:
				{
				_localctx = new ArrayLiteralExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(780);
				arrayLiteral();
				}
				break;
			case 22:
				{
				_localctx = new ObjectLiteralExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(781);
				objectLiteral();
				}
				break;
			case 23:
				{
				_localctx = new ParenthesizedExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(782);
				match(OpenParen);
				setState(783);
				expressionSequence();
				setState(784);
				match(CloseParen);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(869);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,93,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					setState(867);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,92,_ctx) ) {
					case 1:
						{
						_localctx = new PowerExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(788);
						if (!(precpred(_ctx, 27))) throw new FailedPredicateException(this, "precpred(_ctx, 27)");
						setState(789);
						match(Power);
						setState(790);
						singleExpression(27);
						}
						break;
					case 2:
						{
						_localctx = new MultiplicativeExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(791);
						if (!(precpred(_ctx, 26))) throw new FailedPredicateException(this, "precpred(_ctx, 26)");
						setState(792);
						_la = _input.LA(1);
						if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << Multiply) | (1L << Divide) | (1L << Modulus))) != 0)) ) {
						_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(793);
						singleExpression(27);
						}
						break;
					case 3:
						{
						_localctx = new AdditiveExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(794);
						if (!(precpred(_ctx, 25))) throw new FailedPredicateException(this, "precpred(_ctx, 25)");
						setState(795);
						_la = _input.LA(1);
						if ( !(_la==Plus || _la==Minus) ) {
						_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(796);
						singleExpression(26);
						}
						break;
					case 4:
						{
						_localctx = new CoalesceExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(797);
						if (!(precpred(_ctx, 24))) throw new FailedPredicateException(this, "precpred(_ctx, 24)");
						setState(798);
						match(NullCoalesce);
						setState(799);
						singleExpression(25);
						}
						break;
					case 5:
						{
						_localctx = new BitShiftExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(800);
						if (!(precpred(_ctx, 23))) throw new FailedPredicateException(this, "precpred(_ctx, 23)");
						setState(801);
						_la = _input.LA(1);
						if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << RightShiftArithmetic) | (1L << LeftShiftArithmetic) | (1L << RightShiftLogical))) != 0)) ) {
						_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(802);
						singleExpression(24);
						}
						break;
					case 6:
						{
						_localctx = new RelationalExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(803);
						if (!(precpred(_ctx, 22))) throw new FailedPredicateException(this, "precpred(_ctx, 22)");
						setState(804);
						_la = _input.LA(1);
						if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << LessThan) | (1L << MoreThan) | (1L << LessThanEquals) | (1L << GreaterThanEquals))) != 0)) ) {
						_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(805);
						singleExpression(23);
						}
						break;
					case 7:
						{
						_localctx = new InstanceofExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(806);
						if (!(precpred(_ctx, 21))) throw new FailedPredicateException(this, "precpred(_ctx, 21)");
						setState(807);
						match(Instanceof);
						setState(808);
						singleExpression(22);
						}
						break;
					case 8:
						{
						_localctx = new InExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(809);
						if (!(precpred(_ctx, 20))) throw new FailedPredicateException(this, "precpred(_ctx, 20)");
						setState(810);
						match(In);
						setState(811);
						singleExpression(21);
						}
						break;
					case 9:
						{
						_localctx = new EqualityExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(812);
						if (!(precpred(_ctx, 19))) throw new FailedPredicateException(this, "precpred(_ctx, 19)");
						setState(813);
						_la = _input.LA(1);
						if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << Equals_) | (1L << NotEquals) | (1L << IdentityEquals) | (1L << IdentityNotEquals))) != 0)) ) {
						_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(814);
						singleExpression(20);
						}
						break;
					case 10:
						{
						_localctx = new BitAndExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(815);
						if (!(precpred(_ctx, 18))) throw new FailedPredicateException(this, "precpred(_ctx, 18)");
						setState(816);
						match(BitAnd);
						setState(817);
						singleExpression(19);
						}
						break;
					case 11:
						{
						_localctx = new BitXOrExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(818);
						if (!(precpred(_ctx, 17))) throw new FailedPredicateException(this, "precpred(_ctx, 17)");
						setState(819);
						match(BitXOr);
						setState(820);
						singleExpression(18);
						}
						break;
					case 12:
						{
						_localctx = new BitOrExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(821);
						if (!(precpred(_ctx, 16))) throw new FailedPredicateException(this, "precpred(_ctx, 16)");
						setState(822);
						match(BitOr);
						setState(823);
						singleExpression(17);
						}
						break;
					case 13:
						{
						_localctx = new LogicalAndExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(824);
						if (!(precpred(_ctx, 15))) throw new FailedPredicateException(this, "precpred(_ctx, 15)");
						setState(825);
						match(And);
						setState(826);
						singleExpression(16);
						}
						break;
					case 14:
						{
						_localctx = new LogicalOrExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(827);
						if (!(precpred(_ctx, 14))) throw new FailedPredicateException(this, "precpred(_ctx, 14)");
						setState(828);
						match(Or);
						setState(829);
						singleExpression(15);
						}
						break;
					case 15:
						{
						_localctx = new TernaryExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(830);
						if (!(precpred(_ctx, 13))) throw new FailedPredicateException(this, "precpred(_ctx, 13)");
						setState(831);
						match(QuestionMark);
						setState(832);
						singleExpression(0);
						setState(833);
						match(Colon);
						setState(834);
						singleExpression(14);
						}
						break;
					case 16:
						{
						_localctx = new AssignmentExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(836);
						if (!(precpred(_ctx, 12))) throw new FailedPredicateException(this, "precpred(_ctx, 12)");
						setState(837);
						match(Assign);
						setState(838);
						singleExpression(12);
						}
						break;
					case 17:
						{
						_localctx = new AssignmentOperatorExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(839);
						if (!(precpred(_ctx, 11))) throw new FailedPredicateException(this, "precpred(_ctx, 11)");
						setState(840);
						assignmentOperator();
						setState(841);
						singleExpression(11);
						}
						break;
					case 18:
						{
						_localctx = new MemberIndexExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(843);
						if (!(precpred(_ctx, 44))) throw new FailedPredicateException(this, "precpred(_ctx, 44)");
						setState(844);
						match(OpenBracket);
						setState(845);
						expressionSequence();
						setState(846);
						match(CloseBracket);
						}
						break;
					case 19:
						{
						_localctx = new MemberDotExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(848);
						if (!(precpred(_ctx, 43))) throw new FailedPredicateException(this, "precpred(_ctx, 43)");
						setState(850);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==QuestionMark) {
							{
							setState(849);
							match(QuestionMark);
							}
						}

						setState(852);
						match(Dot);
						setState(854);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==Hashtag) {
							{
							setState(853);
							match(Hashtag);
							}
						}

						setState(856);
						identifierName();
						}
						break;
					case 20:
						{
						_localctx = new ArgumentsExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(857);
						if (!(precpred(_ctx, 42))) throw new FailedPredicateException(this, "precpred(_ctx, 42)");
						setState(858);
						arguments();
						}
						break;
					case 21:
						{
						_localctx = new PostIncrementExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(859);
						if (!(precpred(_ctx, 39))) throw new FailedPredicateException(this, "precpred(_ctx, 39)");
						setState(860);
						if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
						setState(861);
						match(PlusPlus);
						}
						break;
					case 22:
						{
						_localctx = new PostDecreaseExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(862);
						if (!(precpred(_ctx, 38))) throw new FailedPredicateException(this, "precpred(_ctx, 38)");
						setState(863);
						if (!(this.notLineTerminator())) throw new FailedPredicateException(this, "this.notLineTerminator()");
						setState(864);
						match(MinusMinus);
						}
						break;
					case 23:
						{
						_localctx = new TemplateStringExpressionContext(new SingleExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_singleExpression);
						setState(865);
						if (!(precpred(_ctx, 9))) throw new FailedPredicateException(this, "precpred(_ctx, 9)");
						setState(866);
						match(TemplateStringLiteral);
						}
						break;
					}
					} 
				}
				setState(871);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,93,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	public static class AssignableContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public ArrayLiteralContext arrayLiteral() {
			return getRuleContext(ArrayLiteralContext.class,0);
		}
		public ObjectLiteralContext objectLiteral() {
			return getRuleContext(ObjectLiteralContext.class,0);
		}
		public AssignableContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_assignable; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAssignable(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAssignable(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAssignable(this);
			else return visitor.visitChildren(this);
		}
	}

	public final AssignableContext assignable() throws RecognitionException {
		AssignableContext _localctx = new AssignableContext(_ctx, getState());
		enterRule(_localctx, 116, RULE_assignable);
		try {
			setState(875);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Async:
			case NonStrictLet:
			case Identifier:
				enterOuterAlt(_localctx, 1);
				{
				setState(872);
				identifier();
				}
				break;
			case OpenBracket:
				enterOuterAlt(_localctx, 2);
				{
				setState(873);
				arrayLiteral();
				}
				break;
			case OpenBrace:
				enterOuterAlt(_localctx, 3);
				{
				setState(874);
				objectLiteral();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ObjectLiteralContext extends ParserRuleContext {
		public List<PropertyAssignmentContext> propertyAssignment() {
			return getRuleContexts(PropertyAssignmentContext.class);
		}
		public PropertyAssignmentContext propertyAssignment(int i) {
			return getRuleContext(PropertyAssignmentContext.class,i);
		}
		public ObjectLiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_objectLiteral; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterObjectLiteral(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitObjectLiteral(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitObjectLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ObjectLiteralContext objectLiteral() throws RecognitionException {
		ObjectLiteralContext _localctx = new ObjectLiteralContext(_ctx, getState());
		enterRule(_localctx, 118, RULE_objectLiteral);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(877);
			match(OpenBrace);
			setState(886);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,96,_ctx) ) {
			case 1:
				{
				setState(878);
				propertyAssignment();
				setState(883);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,95,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(879);
						match(Comma);
						setState(880);
						propertyAssignment();
						}
						} 
					}
					setState(885);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,95,_ctx);
				}
				}
				break;
			}
			setState(889);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==Comma) {
				{
				setState(888);
				match(Comma);
				}
			}

			setState(891);
			match(CloseBrace);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class AnoymousFunctionContext extends ParserRuleContext {
		public AnoymousFunctionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_anoymousFunction; }
	 
		public AnoymousFunctionContext() { }
		public void copyFrom(AnoymousFunctionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class AnoymousFunctionDeclContext extends AnoymousFunctionContext {
		public TerminalNode Function() { return getToken(JavaScriptParser.Function, 0); }
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public TerminalNode Async() { return getToken(JavaScriptParser.Async, 0); }
		public FormalParameterListContext formalParameterList() {
			return getRuleContext(FormalParameterListContext.class,0);
		}
		public AnoymousFunctionDeclContext(AnoymousFunctionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAnoymousFunctionDecl(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAnoymousFunctionDecl(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAnoymousFunctionDecl(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class ArrowFunctionContext extends AnoymousFunctionContext {
		public ArrowFunctionParametersContext arrowFunctionParameters() {
			return getRuleContext(ArrowFunctionParametersContext.class,0);
		}
		public ArrowFunctionBodyContext arrowFunctionBody() {
			return getRuleContext(ArrowFunctionBodyContext.class,0);
		}
		public TerminalNode Async() { return getToken(JavaScriptParser.Async, 0); }
		public ArrowFunctionContext(AnoymousFunctionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArrowFunction(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArrowFunction(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArrowFunction(this);
			else return visitor.visitChildren(this);
		}
	}
	public static class FunctionDeclContext extends AnoymousFunctionContext {
		public FunctionDeclarationContext functionDeclaration() {
			return getRuleContext(FunctionDeclarationContext.class,0);
		}
		public FunctionDeclContext(AnoymousFunctionContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterFunctionDecl(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitFunctionDecl(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitFunctionDecl(this);
			else return visitor.visitChildren(this);
		}
	}

	public final AnoymousFunctionContext anoymousFunction() throws RecognitionException {
		AnoymousFunctionContext _localctx = new AnoymousFunctionContext(_ctx, getState());
		enterRule(_localctx, 120, RULE_anoymousFunction);
		int _la;
		try {
			setState(917);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,102,_ctx) ) {
			case 1:
				_localctx = new FunctionDeclContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(893);
				functionDeclaration();
				}
				break;
			case 2:
				_localctx = new AnoymousFunctionDeclContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(895);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Async) {
					{
					setState(894);
					match(Async);
					}
				}

				setState(897);
				match(Function);
				setState(899);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==Multiply) {
					{
					setState(898);
					match(Multiply);
					}
				}

				setState(901);
				match(OpenParen);
				setState(903);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << OpenBracket) | (1L << OpenBrace) | (1L << Ellipsis))) != 0) || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(902);
					formalParameterList();
					}
				}

				setState(905);
				match(CloseParen);
				setState(906);
				match(OpenBrace);
				setState(907);
				functionBody();
				setState(908);
				match(CloseBrace);
				}
				break;
			case 3:
				_localctx = new ArrowFunctionContext(_localctx);
				enterOuterAlt(_localctx, 3);
				{
				setState(911);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,101,_ctx) ) {
				case 1:
					{
					setState(910);
					match(Async);
					}
					break;
				}
				setState(913);
				arrowFunctionParameters();
				setState(914);
				match(ARROW);
				setState(915);
				arrowFunctionBody();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArrowFunctionParametersContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public FormalParameterListContext formalParameterList() {
			return getRuleContext(FormalParameterListContext.class,0);
		}
		public ArrowFunctionParametersContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arrowFunctionParameters; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArrowFunctionParameters(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArrowFunctionParameters(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArrowFunctionParameters(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArrowFunctionParametersContext arrowFunctionParameters() throws RecognitionException {
		ArrowFunctionParametersContext _localctx = new ArrowFunctionParametersContext(_ctx, getState());
		enterRule(_localctx, 122, RULE_arrowFunctionParameters);
		int _la;
		try {
			setState(925);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Async:
			case NonStrictLet:
			case Identifier:
				enterOuterAlt(_localctx, 1);
				{
				setState(919);
				identifier();
				}
				break;
			case OpenParen:
				enterOuterAlt(_localctx, 2);
				{
				setState(920);
				match(OpenParen);
				setState(922);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << OpenBracket) | (1L << OpenBrace) | (1L << Ellipsis))) != 0) || ((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) {
					{
					setState(921);
					formalParameterList();
					}
				}

				setState(924);
				match(CloseParen);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArrowFunctionBodyContext extends ParserRuleContext {
		public SingleExpressionContext singleExpression() {
			return getRuleContext(SingleExpressionContext.class,0);
		}
		public FunctionBodyContext functionBody() {
			return getRuleContext(FunctionBodyContext.class,0);
		}
		public ArrowFunctionBodyContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arrowFunctionBody; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterArrowFunctionBody(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitArrowFunctionBody(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitArrowFunctionBody(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArrowFunctionBodyContext arrowFunctionBody() throws RecognitionException {
		ArrowFunctionBodyContext _localctx = new ArrowFunctionBodyContext(_ctx, getState());
		enterRule(_localctx, 124, RULE_arrowFunctionBody);
		try {
			setState(932);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,105,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(927);
				singleExpression(0);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(928);
				match(OpenBrace);
				setState(929);
				functionBody();
				setState(930);
				match(CloseBrace);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class AssignmentOperatorContext extends ParserRuleContext {
		public AssignmentOperatorContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_assignmentOperator; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterAssignmentOperator(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitAssignmentOperator(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitAssignmentOperator(this);
			else return visitor.visitChildren(this);
		}
	}

	public final AssignmentOperatorContext assignmentOperator() throws RecognitionException {
		AssignmentOperatorContext _localctx = new AssignmentOperatorContext(_ctx, getState());
		enterRule(_localctx, 126, RULE_assignmentOperator);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(934);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << MultiplyAssign) | (1L << DivideAssign) | (1L << ModulusAssign) | (1L << PlusAssign) | (1L << MinusAssign) | (1L << LeftShiftArithmeticAssign) | (1L << RightShiftArithmeticAssign) | (1L << RightShiftLogicalAssign) | (1L << BitAndAssign) | (1L << BitXorAssign) | (1L << BitOrAssign) | (1L << PowerAssign))) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LiteralContext extends ParserRuleContext {
		public TerminalNode NullLiteral() { return getToken(JavaScriptParser.NullLiteral, 0); }
		public TerminalNode BooleanLiteral() { return getToken(JavaScriptParser.BooleanLiteral, 0); }
		public TerminalNode StringLiteral() { return getToken(JavaScriptParser.StringLiteral, 0); }
		public TerminalNode TemplateStringLiteral() { return getToken(JavaScriptParser.TemplateStringLiteral, 0); }
		public TerminalNode RegularExpressionLiteral() { return getToken(JavaScriptParser.RegularExpressionLiteral, 0); }
		public NumericLiteralContext numericLiteral() {
			return getRuleContext(NumericLiteralContext.class,0);
		}
		public BigintLiteralContext bigintLiteral() {
			return getRuleContext(BigintLiteralContext.class,0);
		}
		public LiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_literal; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLiteral(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLiteral(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LiteralContext literal() throws RecognitionException {
		LiteralContext _localctx = new LiteralContext(_ctx, getState());
		enterRule(_localctx, 128, RULE_literal);
		try {
			setState(943);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case NullLiteral:
				enterOuterAlt(_localctx, 1);
				{
				setState(936);
				match(NullLiteral);
				}
				break;
			case BooleanLiteral:
				enterOuterAlt(_localctx, 2);
				{
				setState(937);
				match(BooleanLiteral);
				}
				break;
			case StringLiteral:
				enterOuterAlt(_localctx, 3);
				{
				setState(938);
				match(StringLiteral);
				}
				break;
			case TemplateStringLiteral:
				enterOuterAlt(_localctx, 4);
				{
				setState(939);
				match(TemplateStringLiteral);
				}
				break;
			case RegularExpressionLiteral:
				enterOuterAlt(_localctx, 5);
				{
				setState(940);
				match(RegularExpressionLiteral);
				}
				break;
			case DecimalLiteral:
			case HexIntegerLiteral:
			case OctalIntegerLiteral:
			case OctalIntegerLiteral2:
			case BinaryIntegerLiteral:
				enterOuterAlt(_localctx, 6);
				{
				setState(941);
				numericLiteral();
				}
				break;
			case BigHexIntegerLiteral:
			case BigOctalIntegerLiteral:
			case BigBinaryIntegerLiteral:
			case BigDecimalIntegerLiteral:
				enterOuterAlt(_localctx, 7);
				{
				setState(942);
				bigintLiteral();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class NumericLiteralContext extends ParserRuleContext {
		public TerminalNode DecimalLiteral() { return getToken(JavaScriptParser.DecimalLiteral, 0); }
		public TerminalNode HexIntegerLiteral() { return getToken(JavaScriptParser.HexIntegerLiteral, 0); }
		public TerminalNode OctalIntegerLiteral() { return getToken(JavaScriptParser.OctalIntegerLiteral, 0); }
		public TerminalNode OctalIntegerLiteral2() { return getToken(JavaScriptParser.OctalIntegerLiteral2, 0); }
		public TerminalNode BinaryIntegerLiteral() { return getToken(JavaScriptParser.BinaryIntegerLiteral, 0); }
		public NumericLiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_numericLiteral; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterNumericLiteral(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitNumericLiteral(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitNumericLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final NumericLiteralContext numericLiteral() throws RecognitionException {
		NumericLiteralContext _localctx = new NumericLiteralContext(_ctx, getState());
		enterRule(_localctx, 130, RULE_numericLiteral);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(945);
			_la = _input.LA(1);
			if ( !(((((_la - 61)) & ~0x3f) == 0 && ((1L << (_la - 61)) & ((1L << (DecimalLiteral - 61)) | (1L << (HexIntegerLiteral - 61)) | (1L << (OctalIntegerLiteral - 61)) | (1L << (OctalIntegerLiteral2 - 61)) | (1L << (BinaryIntegerLiteral - 61)))) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class BigintLiteralContext extends ParserRuleContext {
		public TerminalNode BigDecimalIntegerLiteral() { return getToken(JavaScriptParser.BigDecimalIntegerLiteral, 0); }
		public TerminalNode BigHexIntegerLiteral() { return getToken(JavaScriptParser.BigHexIntegerLiteral, 0); }
		public TerminalNode BigOctalIntegerLiteral() { return getToken(JavaScriptParser.BigOctalIntegerLiteral, 0); }
		public TerminalNode BigBinaryIntegerLiteral() { return getToken(JavaScriptParser.BigBinaryIntegerLiteral, 0); }
		public BigintLiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_bigintLiteral; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterBigintLiteral(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitBigintLiteral(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitBigintLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final BigintLiteralContext bigintLiteral() throws RecognitionException {
		BigintLiteralContext _localctx = new BigintLiteralContext(_ctx, getState());
		enterRule(_localctx, 132, RULE_bigintLiteral);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(947);
			_la = _input.LA(1);
			if ( !(((((_la - 66)) & ~0x3f) == 0 && ((1L << (_la - 66)) & ((1L << (BigHexIntegerLiteral - 66)) | (1L << (BigOctalIntegerLiteral - 66)) | (1L << (BigBinaryIntegerLiteral - 66)) | (1L << (BigDecimalIntegerLiteral - 66)))) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class GetterContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public PropertyNameContext propertyName() {
			return getRuleContext(PropertyNameContext.class,0);
		}
		public GetterContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_getter; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterGetter(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitGetter(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitGetter(this);
			else return visitor.visitChildren(this);
		}
	}

	public final GetterContext getter() throws RecognitionException {
		GetterContext _localctx = new GetterContext(_ctx, getState());
		enterRule(_localctx, 134, RULE_getter);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(949);
			if (!(this.n("get"))) throw new FailedPredicateException(this, "this.n(\"get\")");
			setState(950);
			identifier();
			setState(951);
			propertyName();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SetterContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public PropertyNameContext propertyName() {
			return getRuleContext(PropertyNameContext.class,0);
		}
		public SetterContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_setter; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterSetter(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitSetter(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitSetter(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SetterContext setter() throws RecognitionException {
		SetterContext _localctx = new SetterContext(_ctx, getState());
		enterRule(_localctx, 136, RULE_setter);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(953);
			if (!(this.n("set"))) throw new FailedPredicateException(this, "this.n(\"set\")");
			setState(954);
			identifier();
			setState(955);
			propertyName();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class IdentifierNameContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public ReservedWordContext reservedWord() {
			return getRuleContext(ReservedWordContext.class,0);
		}
		public IdentifierNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_identifierName; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterIdentifierName(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitIdentifierName(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitIdentifierName(this);
			else return visitor.visitChildren(this);
		}
	}

	public final IdentifierNameContext identifierName() throws RecognitionException {
		IdentifierNameContext _localctx = new IdentifierNameContext(_ctx, getState());
		enterRule(_localctx, 138, RULE_identifierName);
		try {
			setState(959);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,107,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(957);
				identifier();
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(958);
				reservedWord();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class IdentifierContext extends ParserRuleContext {
		public TerminalNode Identifier() { return getToken(JavaScriptParser.Identifier, 0); }
		public TerminalNode NonStrictLet() { return getToken(JavaScriptParser.NonStrictLet, 0); }
		public TerminalNode Async() { return getToken(JavaScriptParser.Async, 0); }
		public IdentifierContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_identifier; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterIdentifier(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitIdentifier(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitIdentifier(this);
			else return visitor.visitChildren(this);
		}
	}

	public final IdentifierContext identifier() throws RecognitionException {
		IdentifierContext _localctx = new IdentifierContext(_ctx, getState());
		enterRule(_localctx, 140, RULE_identifier);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(961);
			_la = _input.LA(1);
			if ( !(((((_la - 105)) & ~0x3f) == 0 && ((1L << (_la - 105)) & ((1L << (Async - 105)) | (1L << (NonStrictLet - 105)) | (1L << (Identifier - 105)))) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ReservedWordContext extends ParserRuleContext {
		public KeywordContext keyword() {
			return getRuleContext(KeywordContext.class,0);
		}
		public TerminalNode NullLiteral() { return getToken(JavaScriptParser.NullLiteral, 0); }
		public TerminalNode BooleanLiteral() { return getToken(JavaScriptParser.BooleanLiteral, 0); }
		public ReservedWordContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_reservedWord; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterReservedWord(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitReservedWord(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitReservedWord(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ReservedWordContext reservedWord() throws RecognitionException {
		ReservedWordContext _localctx = new ReservedWordContext(_ctx, getState());
		enterRule(_localctx, 142, RULE_reservedWord);
		try {
			setState(966);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Break:
			case Do:
			case Instanceof:
			case Typeof:
			case Case:
			case Else:
			case New:
			case Var:
			case Catch:
			case Finally:
			case Return:
			case Void:
			case Continue:
			case For:
			case Switch:
			case While:
			case Debugger:
			case Function:
			case This:
			case With:
			case Default:
			case If:
			case Throw:
			case Delete:
			case In:
			case Try:
			case As:
			case From:
			case Class:
			case Enum:
			case Extends:
			case Super:
			case Const:
			case Export:
			case Import:
			case Async:
			case Await:
			case Implements:
			case StrictLet:
			case NonStrictLet:
			case Private:
			case Public:
			case Interface:
			case Package:
			case Protected:
			case Static:
			case Yield:
				enterOuterAlt(_localctx, 1);
				{
				setState(963);
				keyword();
				}
				break;
			case NullLiteral:
				enterOuterAlt(_localctx, 2);
				{
				setState(964);
				match(NullLiteral);
				}
				break;
			case BooleanLiteral:
				enterOuterAlt(_localctx, 3);
				{
				setState(965);
				match(BooleanLiteral);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class KeywordContext extends ParserRuleContext {
		public TerminalNode Break() { return getToken(JavaScriptParser.Break, 0); }
		public TerminalNode Do() { return getToken(JavaScriptParser.Do, 0); }
		public TerminalNode Instanceof() { return getToken(JavaScriptParser.Instanceof, 0); }
		public TerminalNode Typeof() { return getToken(JavaScriptParser.Typeof, 0); }
		public TerminalNode Case() { return getToken(JavaScriptParser.Case, 0); }
		public TerminalNode Else() { return getToken(JavaScriptParser.Else, 0); }
		public TerminalNode New() { return getToken(JavaScriptParser.New, 0); }
		public TerminalNode Var() { return getToken(JavaScriptParser.Var, 0); }
		public TerminalNode Catch() { return getToken(JavaScriptParser.Catch, 0); }
		public TerminalNode Finally() { return getToken(JavaScriptParser.Finally, 0); }
		public TerminalNode Return() { return getToken(JavaScriptParser.Return, 0); }
		public TerminalNode Void() { return getToken(JavaScriptParser.Void, 0); }
		public TerminalNode Continue() { return getToken(JavaScriptParser.Continue, 0); }
		public TerminalNode For() { return getToken(JavaScriptParser.For, 0); }
		public TerminalNode Switch() { return getToken(JavaScriptParser.Switch, 0); }
		public TerminalNode While() { return getToken(JavaScriptParser.While, 0); }
		public TerminalNode Debugger() { return getToken(JavaScriptParser.Debugger, 0); }
		public TerminalNode Function() { return getToken(JavaScriptParser.Function, 0); }
		public TerminalNode This() { return getToken(JavaScriptParser.This, 0); }
		public TerminalNode With() { return getToken(JavaScriptParser.With, 0); }
		public TerminalNode Default() { return getToken(JavaScriptParser.Default, 0); }
		public TerminalNode If() { return getToken(JavaScriptParser.If, 0); }
		public TerminalNode Throw() { return getToken(JavaScriptParser.Throw, 0); }
		public TerminalNode Delete() { return getToken(JavaScriptParser.Delete, 0); }
		public TerminalNode In() { return getToken(JavaScriptParser.In, 0); }
		public TerminalNode Try() { return getToken(JavaScriptParser.Try, 0); }
		public TerminalNode Class() { return getToken(JavaScriptParser.Class, 0); }
		public TerminalNode Enum() { return getToken(JavaScriptParser.Enum, 0); }
		public TerminalNode Extends() { return getToken(JavaScriptParser.Extends, 0); }
		public TerminalNode Super() { return getToken(JavaScriptParser.Super, 0); }
		public TerminalNode Const() { return getToken(JavaScriptParser.Const, 0); }
		public TerminalNode Export() { return getToken(JavaScriptParser.Export, 0); }
		public TerminalNode Import() { return getToken(JavaScriptParser.Import, 0); }
		public TerminalNode Implements() { return getToken(JavaScriptParser.Implements, 0); }
		public LetContext let() {
			return getRuleContext(LetContext.class,0);
		}
		public TerminalNode Private() { return getToken(JavaScriptParser.Private, 0); }
		public TerminalNode Public() { return getToken(JavaScriptParser.Public, 0); }
		public TerminalNode Interface() { return getToken(JavaScriptParser.Interface, 0); }
		public TerminalNode Package() { return getToken(JavaScriptParser.Package, 0); }
		public TerminalNode Protected() { return getToken(JavaScriptParser.Protected, 0); }
		public TerminalNode Static() { return getToken(JavaScriptParser.Static, 0); }
		public TerminalNode Yield() { return getToken(JavaScriptParser.Yield, 0); }
		public TerminalNode Async() { return getToken(JavaScriptParser.Async, 0); }
		public TerminalNode Await() { return getToken(JavaScriptParser.Await, 0); }
		public TerminalNode From() { return getToken(JavaScriptParser.From, 0); }
		public TerminalNode As() { return getToken(JavaScriptParser.As, 0); }
		public KeywordContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_keyword; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterKeyword(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitKeyword(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitKeyword(this);
			else return visitor.visitChildren(this);
		}
	}

	public final KeywordContext keyword() throws RecognitionException {
		KeywordContext _localctx = new KeywordContext(_ctx, getState());
		enterRule(_localctx, 144, RULE_keyword);
		try {
			setState(1014);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case Break:
				enterOuterAlt(_localctx, 1);
				{
				setState(968);
				match(Break);
				}
				break;
			case Do:
				enterOuterAlt(_localctx, 2);
				{
				setState(969);
				match(Do);
				}
				break;
			case Instanceof:
				enterOuterAlt(_localctx, 3);
				{
				setState(970);
				match(Instanceof);
				}
				break;
			case Typeof:
				enterOuterAlt(_localctx, 4);
				{
				setState(971);
				match(Typeof);
				}
				break;
			case Case:
				enterOuterAlt(_localctx, 5);
				{
				setState(972);
				match(Case);
				}
				break;
			case Else:
				enterOuterAlt(_localctx, 6);
				{
				setState(973);
				match(Else);
				}
				break;
			case New:
				enterOuterAlt(_localctx, 7);
				{
				setState(974);
				match(New);
				}
				break;
			case Var:
				enterOuterAlt(_localctx, 8);
				{
				setState(975);
				match(Var);
				}
				break;
			case Catch:
				enterOuterAlt(_localctx, 9);
				{
				setState(976);
				match(Catch);
				}
				break;
			case Finally:
				enterOuterAlt(_localctx, 10);
				{
				setState(977);
				match(Finally);
				}
				break;
			case Return:
				enterOuterAlt(_localctx, 11);
				{
				setState(978);
				match(Return);
				}
				break;
			case Void:
				enterOuterAlt(_localctx, 12);
				{
				setState(979);
				match(Void);
				}
				break;
			case Continue:
				enterOuterAlt(_localctx, 13);
				{
				setState(980);
				match(Continue);
				}
				break;
			case For:
				enterOuterAlt(_localctx, 14);
				{
				setState(981);
				match(For);
				}
				break;
			case Switch:
				enterOuterAlt(_localctx, 15);
				{
				setState(982);
				match(Switch);
				}
				break;
			case While:
				enterOuterAlt(_localctx, 16);
				{
				setState(983);
				match(While);
				}
				break;
			case Debugger:
				enterOuterAlt(_localctx, 17);
				{
				setState(984);
				match(Debugger);
				}
				break;
			case Function:
				enterOuterAlt(_localctx, 18);
				{
				setState(985);
				match(Function);
				}
				break;
			case This:
				enterOuterAlt(_localctx, 19);
				{
				setState(986);
				match(This);
				}
				break;
			case With:
				enterOuterAlt(_localctx, 20);
				{
				setState(987);
				match(With);
				}
				break;
			case Default:
				enterOuterAlt(_localctx, 21);
				{
				setState(988);
				match(Default);
				}
				break;
			case If:
				enterOuterAlt(_localctx, 22);
				{
				setState(989);
				match(If);
				}
				break;
			case Throw:
				enterOuterAlt(_localctx, 23);
				{
				setState(990);
				match(Throw);
				}
				break;
			case Delete:
				enterOuterAlt(_localctx, 24);
				{
				setState(991);
				match(Delete);
				}
				break;
			case In:
				enterOuterAlt(_localctx, 25);
				{
				setState(992);
				match(In);
				}
				break;
			case Try:
				enterOuterAlt(_localctx, 26);
				{
				setState(993);
				match(Try);
				}
				break;
			case Class:
				enterOuterAlt(_localctx, 27);
				{
				setState(994);
				match(Class);
				}
				break;
			case Enum:
				enterOuterAlt(_localctx, 28);
				{
				setState(995);
				match(Enum);
				}
				break;
			case Extends:
				enterOuterAlt(_localctx, 29);
				{
				setState(996);
				match(Extends);
				}
				break;
			case Super:
				enterOuterAlt(_localctx, 30);
				{
				setState(997);
				match(Super);
				}
				break;
			case Const:
				enterOuterAlt(_localctx, 31);
				{
				setState(998);
				match(Const);
				}
				break;
			case Export:
				enterOuterAlt(_localctx, 32);
				{
				setState(999);
				match(Export);
				}
				break;
			case Import:
				enterOuterAlt(_localctx, 33);
				{
				setState(1000);
				match(Import);
				}
				break;
			case Implements:
				enterOuterAlt(_localctx, 34);
				{
				setState(1001);
				match(Implements);
				}
				break;
			case StrictLet:
			case NonStrictLet:
				enterOuterAlt(_localctx, 35);
				{
				setState(1002);
				let();
				}
				break;
			case Private:
				enterOuterAlt(_localctx, 36);
				{
				setState(1003);
				match(Private);
				}
				break;
			case Public:
				enterOuterAlt(_localctx, 37);
				{
				setState(1004);
				match(Public);
				}
				break;
			case Interface:
				enterOuterAlt(_localctx, 38);
				{
				setState(1005);
				match(Interface);
				}
				break;
			case Package:
				enterOuterAlt(_localctx, 39);
				{
				setState(1006);
				match(Package);
				}
				break;
			case Protected:
				enterOuterAlt(_localctx, 40);
				{
				setState(1007);
				match(Protected);
				}
				break;
			case Static:
				enterOuterAlt(_localctx, 41);
				{
				setState(1008);
				match(Static);
				}
				break;
			case Yield:
				enterOuterAlt(_localctx, 42);
				{
				setState(1009);
				match(Yield);
				}
				break;
			case Async:
				enterOuterAlt(_localctx, 43);
				{
				setState(1010);
				match(Async);
				}
				break;
			case Await:
				enterOuterAlt(_localctx, 44);
				{
				setState(1011);
				match(Await);
				}
				break;
			case From:
				enterOuterAlt(_localctx, 45);
				{
				setState(1012);
				match(From);
				}
				break;
			case As:
				enterOuterAlt(_localctx, 46);
				{
				setState(1013);
				match(As);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LetContext extends ParserRuleContext {
		public TerminalNode NonStrictLet() { return getToken(JavaScriptParser.NonStrictLet, 0); }
		public TerminalNode StrictLet() { return getToken(JavaScriptParser.StrictLet, 0); }
		public LetContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_let; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterLet(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitLet(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitLet(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LetContext let() throws RecognitionException {
		LetContext _localctx = new LetContext(_ctx, getState());
		enterRule(_localctx, 146, RULE_let);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(1016);
			_la = _input.LA(1);
			if ( !(_la==StrictLet || _la==NonStrictLet) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class EosContext extends ParserRuleContext {
		public TerminalNode SemiColon() { return getToken(JavaScriptParser.SemiColon, 0); }
		public TerminalNode EOF() { return getToken(JavaScriptParser.EOF, 0); }
		public EosContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_eos; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).enterEos(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof JavaScriptParserListener ) ((JavaScriptParserListener)listener).exitEos(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof JavaScriptParserVisitor ) return ((JavaScriptParserVisitor<? extends T>)visitor).visitEos(this);
			else return visitor.visitChildren(this);
		}
	}

	public final EosContext eos() throws RecognitionException {
		EosContext _localctx = new EosContext(_ctx, getState());
		enterRule(_localctx, 148, RULE_eos);
		try {
			setState(1022);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,110,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(1018);
				match(SemiColon);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(1019);
				match(EOF);
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				setState(1020);
				if (!(this.lineTerminatorAhead())) throw new FailedPredicateException(this, "this.lineTerminatorAhead()");
				}
				break;
			case 4:
				enterOuterAlt(_localctx, 4);
				{
				setState(1021);
				if (!(this.closeBrace())) throw new FailedPredicateException(this, "this.closeBrace()");
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public boolean sempred(RuleContext _localctx, int ruleIndex, int predIndex) {
		switch (ruleIndex) {
		case 19:
			return expressionStatement_sempred((ExpressionStatementContext)_localctx, predIndex);
		case 21:
			return iterationStatement_sempred((IterationStatementContext)_localctx, predIndex);
		case 23:
			return continueStatement_sempred((ContinueStatementContext)_localctx, predIndex);
		case 24:
			return breakStatement_sempred((BreakStatementContext)_localctx, predIndex);
		case 25:
			return returnStatement_sempred((ReturnStatementContext)_localctx, predIndex);
		case 26:
			return yieldStatement_sempred((YieldStatementContext)_localctx, predIndex);
		case 34:
			return throwStatement_sempred((ThrowStatementContext)_localctx, predIndex);
		case 42:
			return classElement_sempred((ClassElementContext)_localctx, predIndex);
		case 57:
			return singleExpression_sempred((SingleExpressionContext)_localctx, predIndex);
		case 67:
			return getter_sempred((GetterContext)_localctx, predIndex);
		case 68:
			return setter_sempred((SetterContext)_localctx, predIndex);
		case 74:
			return eos_sempred((EosContext)_localctx, predIndex);
		}
		return true;
	}
	private boolean expressionStatement_sempred(ExpressionStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 0:
			return this.notOpenBraceAndNotFunction();
		}
		return true;
	}
	private boolean iterationStatement_sempred(IterationStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 1:
			return this.p("of");
		}
		return true;
	}
	private boolean continueStatement_sempred(ContinueStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 2:
			return this.notLineTerminator();
		}
		return true;
	}
	private boolean breakStatement_sempred(BreakStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 3:
			return this.notLineTerminator();
		}
		return true;
	}
	private boolean returnStatement_sempred(ReturnStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 4:
			return this.notLineTerminator();
		}
		return true;
	}
	private boolean yieldStatement_sempred(YieldStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 5:
			return this.notLineTerminator();
		}
		return true;
	}
	private boolean throwStatement_sempred(ThrowStatementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 6:
			return this.notLineTerminator();
		}
		return true;
	}
	private boolean classElement_sempred(ClassElementContext _localctx, int predIndex) {
		switch (predIndex) {
		case 7:
			return this.n("static");
		}
		return true;
	}
	private boolean singleExpression_sempred(SingleExpressionContext _localctx, int predIndex) {
		switch (predIndex) {
		case 8:
			return precpred(_ctx, 27);
		case 9:
			return precpred(_ctx, 26);
		case 10:
			return precpred(_ctx, 25);
		case 11:
			return precpred(_ctx, 24);
		case 12:
			return precpred(_ctx, 23);
		case 13:
			return precpred(_ctx, 22);
		case 14:
			return precpred(_ctx, 21);
		case 15:
			return precpred(_ctx, 20);
		case 16:
			return precpred(_ctx, 19);
		case 17:
			return precpred(_ctx, 18);
		case 18:
			return precpred(_ctx, 17);
		case 19:
			return precpred(_ctx, 16);
		case 20:
			return precpred(_ctx, 15);
		case 21:
			return precpred(_ctx, 14);
		case 22:
			return precpred(_ctx, 13);
		case 23:
			return precpred(_ctx, 12);
		case 24:
			return precpred(_ctx, 11);
		case 25:
			return precpred(_ctx, 44);
		case 26:
			return precpred(_ctx, 43);
		case 27:
			return precpred(_ctx, 42);
		case 28:
			return precpred(_ctx, 39);
		case 29:
			return this.notLineTerminator();
		case 30:
			return precpred(_ctx, 38);
		case 31:
			return this.notLineTerminator();
		case 32:
			return precpred(_ctx, 9);
		}
		return true;
	}
	private boolean getter_sempred(GetterContext _localctx, int predIndex) {
		switch (predIndex) {
		case 33:
			return this.n("get");
		}
		return true;
	}
	private boolean setter_sempred(SetterContext _localctx, int predIndex) {
		switch (predIndex) {
		case 34:
			return this.n("set");
		}
		return true;
	}
	private boolean eos_sempred(EosContext _localctx, int predIndex) {
		switch (predIndex) {
		case 35:
			return this.lineTerminatorAhead();
		case 36:
			return this.closeBrace();
		}
		return true;
	}

	public static final String _serializedATN =
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3~\u0403\4\2\t\2\4"+
		"\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t"+
		"\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22\t\22"+
		"\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\4\31\t\31"+
		"\4\32\t\32\4\33\t\33\4\34\t\34\4\35\t\35\4\36\t\36\4\37\t\37\4 \t \4!"+
		"\t!\4\"\t\"\4#\t#\4$\t$\4%\t%\4&\t&\4\'\t\'\4(\t(\4)\t)\4*\t*\4+\t+\4"+
		",\t,\4-\t-\4.\t.\4/\t/\4\60\t\60\4\61\t\61\4\62\t\62\4\63\t\63\4\64\t"+
		"\64\4\65\t\65\4\66\t\66\4\67\t\67\48\t8\49\t9\4:\t:\4;\t;\4<\t<\4=\t="+
		"\4>\t>\4?\t?\4@\t@\4A\tA\4B\tB\4C\tC\4D\tD\4E\tE\4F\tF\4G\tG\4H\tH\4I"+
		"\tI\4J\tJ\4K\tK\4L\tL\3\2\5\2\u009a\n\2\3\2\5\2\u009d\n\2\3\2\3\2\3\3"+
		"\3\3\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3"+
		"\4\3\4\3\4\3\4\5\4\u00b7\n\4\3\5\3\5\5\5\u00bb\n\5\3\5\3\5\3\6\6\6\u00c0"+
		"\n\6\r\6\16\6\u00c1\3\7\3\7\3\7\3\b\5\b\u00c8\n\b\3\b\3\b\5\b\u00cc\n"+
		"\b\3\b\3\b\3\b\3\b\3\b\5\b\u00d3\n\b\3\t\3\t\3\t\3\t\7\t\u00d9\n\t\f\t"+
		"\16\t\u00dc\13\t\3\t\3\t\5\t\u00e0\n\t\5\t\u00e2\n\t\3\t\3\t\3\n\3\n\3"+
		"\n\3\13\3\13\5\13\u00eb\n\13\3\13\3\13\5\13\u00ef\n\13\3\f\3\f\3\f\3\r"+
		"\3\r\3\r\5\r\u00f7\n\r\3\16\3\16\3\16\5\16\u00fc\n\16\3\16\3\16\3\16\3"+
		"\16\3\16\3\16\3\16\5\16\u0105\n\16\3\17\3\17\3\17\3\17\3\17\3\17\5\17"+
		"\u010d\n\17\3\17\3\17\5\17\u0111\n\17\3\20\3\20\3\20\5\20\u0116\n\20\3"+
		"\21\3\21\3\21\3\22\3\22\3\22\3\22\7\22\u011f\n\22\f\22\16\22\u0122\13"+
		"\22\3\23\3\23\3\23\5\23\u0127\n\23\3\24\3\24\3\25\3\25\3\25\3\25\3\26"+
		"\3\26\3\26\3\26\3\26\3\26\3\26\5\26\u0136\n\26\3\27\3\27\3\27\3\27\3\27"+
		"\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\5\27"+
		"\u014a\n\27\3\27\3\27\5\27\u014e\n\27\3\27\3\27\5\27\u0152\n\27\3\27\3"+
		"\27\3\27\3\27\3\27\3\27\5\27\u015a\n\27\3\27\3\27\3\27\3\27\3\27\3\27"+
		"\3\27\5\27\u0163\n\27\3\27\3\27\3\27\5\27\u0168\n\27\3\27\3\27\3\27\3"+
		"\27\3\27\3\27\5\27\u0170\n\27\3\30\3\30\3\30\5\30\u0175\n\30\3\31\3\31"+
		"\3\31\5\31\u017a\n\31\3\31\3\31\3\32\3\32\3\32\5\32\u0181\n\32\3\32\3"+
		"\32\3\33\3\33\3\33\5\33\u0188\n\33\3\33\3\33\3\34\3\34\3\34\5\34\u018f"+
		"\n\34\3\34\3\34\3\35\3\35\3\35\3\35\3\35\3\35\3\36\3\36\3\36\3\36\3\36"+
		"\3\36\3\37\3\37\5\37\u01a1\n\37\3\37\3\37\5\37\u01a5\n\37\5\37\u01a7\n"+
		"\37\3\37\3\37\3 \6 \u01ac\n \r \16 \u01ad\3!\3!\3!\3!\5!\u01b4\n!\3\""+
		"\3\"\3\"\5\"\u01b9\n\"\3#\3#\3#\3#\3$\3$\3$\3$\3$\3%\3%\3%\3%\5%\u01c8"+
		"\n%\3%\5%\u01cb\n%\3&\3&\3&\5&\u01d0\n&\3&\5&\u01d3\n&\3&\3&\3\'\3\'\3"+
		"\'\3(\3(\3(\3)\5)\u01de\n)\3)\3)\5)\u01e2\n)\3)\3)\3)\5)\u01e7\n)\3)\3"+
		")\3)\3)\3)\3*\3*\3*\3*\3+\3+\5+\u01f4\n+\3+\3+\7+\u01f8\n+\f+\16+\u01fb"+
		"\13+\3+\3+\3,\3,\3,\3,\7,\u0203\n,\f,\16,\u0206\13,\3,\3,\3,\3,\3,\3,"+
		"\5,\u020e\n,\3,\3,\5,\u0212\n,\3,\3,\3,\3,\5,\u0218\n,\3-\5-\u021b\n-"+
		"\3-\5-\u021e\n-\3-\3-\3-\5-\u0223\n-\3-\3-\3-\3-\3-\3-\5-\u022b\n-\3-"+
		"\5-\u022e\n-\3-\3-\3-\3-\3-\3-\3-\3-\5-\u0238\n-\3-\5-\u023b\n-\3-\3-"+
		"\3-\5-\u0240\n-\3-\3-\3-\3-\3-\5-\u0247\n-\3.\3.\3.\7.\u024c\n.\f.\16"+
		".\u024f\13.\3.\3.\5.\u0253\n.\3.\5.\u0256\n.\3/\3/\3/\5/\u025b\n/\3\60"+
		"\3\60\3\60\3\61\5\61\u0261\n\61\3\62\6\62\u0264\n\62\r\62\16\62\u0265"+
		"\3\63\3\63\3\63\3\63\3\64\7\64\u026d\n\64\f\64\16\64\u0270\13\64\3\64"+
		"\5\64\u0273\n\64\3\64\6\64\u0276\n\64\r\64\16\64\u0277\3\64\7\64\u027b"+
		"\n\64\f\64\16\64\u027e\13\64\3\64\7\64\u0281\n\64\f\64\16\64\u0284\13"+
		"\64\3\65\5\65\u0287\n\65\3\65\3\65\3\66\3\66\3\66\3\66\3\66\3\66\3\66"+
		"\3\66\3\66\3\66\3\66\5\66\u0296\n\66\3\66\5\66\u0299\n\66\3\66\3\66\3"+
		"\66\5\66\u029e\n\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66"+
		"\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\3\66\5\66\u02b5\n\66"+
		"\3\66\5\66\u02b8\n\66\3\67\3\67\3\67\3\67\3\67\3\67\3\67\5\67\u02c1\n"+
		"\67\38\38\38\38\78\u02c7\n8\f8\168\u02ca\138\38\58\u02cd\n8\58\u02cf\n"+
		"8\38\38\39\59\u02d4\n9\39\39\59\u02d8\n9\3:\3:\3:\7:\u02dd\n:\f:\16:\u02e0"+
		"\13:\3;\3;\3;\3;\5;\u02e6\n;\3;\3;\3;\3;\5;\u02ec\n;\3;\3;\3;\3;\3;\3"+
		";\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3"+
		";\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\5;\u0315\n;\3;\3;\3;\3;\3;\3;\3;\3;\3"+
		";\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3"+
		";\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3;\3"+
		";\3;\3;\3;\3;\3;\3;\3;\5;\u0355\n;\3;\3;\5;\u0359\n;\3;\3;\3;\3;\3;\3"+
		";\3;\3;\3;\3;\3;\7;\u0366\n;\f;\16;\u0369\13;\3<\3<\3<\5<\u036e\n<\3="+
		"\3=\3=\3=\7=\u0374\n=\f=\16=\u0377\13=\5=\u0379\n=\3=\5=\u037c\n=\3=\3"+
		"=\3>\3>\5>\u0382\n>\3>\3>\5>\u0386\n>\3>\3>\5>\u038a\n>\3>\3>\3>\3>\3"+
		">\3>\5>\u0392\n>\3>\3>\3>\3>\5>\u0398\n>\3?\3?\3?\5?\u039d\n?\3?\5?\u03a0"+
		"\n?\3@\3@\3@\3@\3@\5@\u03a7\n@\3A\3A\3B\3B\3B\3B\3B\3B\3B\5B\u03b2\nB"+
		"\3C\3C\3D\3D\3E\3E\3E\3E\3F\3F\3F\3F\3G\3G\5G\u03c2\nG\3H\3H\3I\3I\3I"+
		"\5I\u03c9\nI\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J"+
		"\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J\3J"+
		"\3J\3J\3J\3J\5J\u03f9\nJ\3K\3K\3L\3L\3L\3L\5L\u0401\nL\3L\2\3tM\2\4\6"+
		"\b\n\f\16\20\22\24\26\30\32\34\36 \"$&(*,.\60\62\64\668:<>@BDFHJLNPRT"+
		"VXZ\\^`bdfhjlnprtvxz|~\u0080\u0082\u0084\u0086\u0088\u008a\u008c\u008e"+
		"\u0090\u0092\u0094\u0096\2\f\3\2\32\34\3\2\26\27\3\2 \"\3\2#&\3\2\'*\3"+
		"\2\60;\3\2?C\3\2DG\5\2kkooww\3\2no\2\u04a7\2\u0099\3\2\2\2\4\u00a0\3\2"+
		"\2\2\6\u00b6\3\2\2\2\b\u00b8\3\2\2\2\n\u00bf\3\2\2\2\f\u00c3\3\2\2\2\16"+
		"\u00d2\3\2\2\2\20\u00d4\3\2\2\2\22\u00e5\3\2\2\2\24\u00ea\3\2\2\2\26\u00f0"+
		"\3\2\2\2\30\u00f3\3\2\2\2\32\u0104\3\2\2\2\34\u0110\3\2\2\2\36\u0115\3"+
		"\2\2\2 \u0117\3\2\2\2\"\u011a\3\2\2\2$\u0123\3\2\2\2&\u0128\3\2\2\2(\u012a"+
		"\3\2\2\2*\u012e\3\2\2\2,\u016f\3\2\2\2.\u0174\3\2\2\2\60\u0176\3\2\2\2"+
		"\62\u017d\3\2\2\2\64\u0184\3\2\2\2\66\u018b\3\2\2\28\u0192\3\2\2\2:\u0198"+
		"\3\2\2\2<\u019e\3\2\2\2>\u01ab\3\2\2\2@\u01af\3\2\2\2B\u01b5\3\2\2\2D"+
		"\u01ba\3\2\2\2F\u01be\3\2\2\2H\u01c3\3\2\2\2J\u01cc\3\2\2\2L\u01d6\3\2"+
		"\2\2N\u01d9\3\2\2\2P\u01dd\3\2\2\2R\u01ed\3\2\2\2T\u01f3\3\2\2\2V\u0217"+
		"\3\2\2\2X\u0246\3\2\2\2Z\u0255\3\2\2\2\\\u0257\3\2\2\2^\u025c\3\2\2\2"+
		"`\u0260\3\2\2\2b\u0263\3\2\2\2d\u0267\3\2\2\2f\u026e\3\2\2\2h\u0286\3"+
		"\2\2\2j\u02b7\3\2\2\2l\u02c0\3\2\2\2n\u02c2\3\2\2\2p\u02d3\3\2\2\2r\u02d9"+
		"\3\2\2\2t\u0314\3\2\2\2v\u036d\3\2\2\2x\u036f\3\2\2\2z\u0397\3\2\2\2|"+
		"\u039f\3\2\2\2~\u03a6\3\2\2\2\u0080\u03a8\3\2\2\2\u0082\u03b1\3\2\2\2"+
		"\u0084\u03b3\3\2\2\2\u0086\u03b5\3\2\2\2\u0088\u03b7\3\2\2\2\u008a\u03bb"+
		"\3\2\2\2\u008c\u03c1\3\2\2\2\u008e\u03c3\3\2\2\2\u0090\u03c8\3\2\2\2\u0092"+
		"\u03f8\3\2\2\2\u0094\u03fa\3\2\2\2\u0096\u0400\3\2\2\2\u0098\u009a\7\3"+
		"\2\2\u0099\u0098\3\2\2\2\u0099\u009a\3\2\2\2\u009a\u009c\3\2\2\2\u009b"+
		"\u009d\5b\62\2\u009c\u009b\3\2\2\2\u009c\u009d\3\2\2\2\u009d\u009e\3\2"+
		"\2\2\u009e\u009f\7\2\2\3\u009f\3\3\2\2\2\u00a0\u00a1\5\6\4\2\u00a1\5\3"+
		"\2\2\2\u00a2\u00b7\5\b\5\2\u00a3\u00b7\5 \21\2\u00a4\u00b7\5\f\7\2\u00a5"+
		"\u00b7\5\32\16\2\u00a6\u00b7\5&\24\2\u00a7\u00b7\5R*\2\u00a8\u00b7\5("+
		"\25\2\u00a9\u00b7\5*\26\2\u00aa\u00b7\5,\27\2\u00ab\u00b7\5\60\31\2\u00ac"+
		"\u00b7\5\62\32\2\u00ad\u00b7\5\64\33\2\u00ae\u00b7\5\66\34\2\u00af\u00b7"+
		"\58\35\2\u00b0\u00b7\5D#\2\u00b1\u00b7\5:\36\2\u00b2\u00b7\5F$\2\u00b3"+
		"\u00b7\5H%\2\u00b4\u00b7\5N(\2\u00b5\u00b7\5P)\2\u00b6\u00a2\3\2\2\2\u00b6"+
		"\u00a3\3\2\2\2\u00b6\u00a4\3\2\2\2\u00b6\u00a5\3\2\2\2\u00b6\u00a6\3\2"+
		"\2\2\u00b6\u00a7\3\2\2\2\u00b6\u00a8\3\2\2\2\u00b6\u00a9\3\2\2\2\u00b6"+
		"\u00aa\3\2\2\2\u00b6\u00ab\3\2\2\2\u00b6\u00ac\3\2\2\2\u00b6\u00ad\3\2"+
		"\2\2\u00b6\u00ae\3\2\2\2\u00b6\u00af\3\2\2\2\u00b6\u00b0\3\2\2\2\u00b6"+
		"\u00b1\3\2\2\2\u00b6\u00b2\3\2\2\2\u00b6\u00b3\3\2\2\2\u00b6\u00b4\3\2"+
		"\2\2\u00b6\u00b5\3\2\2\2\u00b7\7\3\2\2\2\u00b8\u00ba\7\13\2\2\u00b9\u00bb"+
		"\5\n\6\2\u00ba\u00b9\3\2\2\2\u00ba\u00bb\3\2\2\2\u00bb\u00bc\3\2\2\2\u00bc"+
		"\u00bd\7\f\2\2\u00bd\t\3\2\2\2\u00be\u00c0\5\6\4\2\u00bf\u00be\3\2\2\2"+
		"\u00c0\u00c1\3\2\2\2\u00c1\u00bf\3\2\2\2\u00c1\u00c2\3\2\2\2\u00c2\13"+
		"\3\2\2\2\u00c3\u00c4\7j\2\2\u00c4\u00c5\5\16\b\2\u00c5\r\3\2\2\2\u00c6"+
		"\u00c8\5\22\n\2\u00c7\u00c6\3\2\2\2\u00c7\u00c8\3\2\2\2\u00c8\u00cb\3"+
		"\2\2\2\u00c9\u00cc\5\24\13\2\u00ca\u00cc\5\20\t\2\u00cb\u00c9\3\2\2\2"+
		"\u00cb\u00ca\3\2\2\2\u00cc\u00cd\3\2\2\2\u00cd\u00ce\5\26\f\2\u00ce\u00cf"+
		"\5\u0096L\2\u00cf\u00d3\3\2\2\2\u00d0\u00d1\7x\2\2\u00d1\u00d3\5\u0096"+
		"L\2\u00d2\u00c7\3\2\2\2\u00d2\u00d0\3\2\2\2\u00d3\17\3\2\2\2\u00d4\u00da"+
		"\7\13\2\2\u00d5\u00d6\5\30\r\2\u00d6\u00d7\7\16\2\2\u00d7\u00d9\3\2\2"+
		"\2\u00d8\u00d5\3\2\2\2\u00d9\u00dc\3\2\2\2\u00da\u00d8\3\2\2\2\u00da\u00db"+
		"\3\2\2\2\u00db\u00e1\3\2\2\2\u00dc\u00da\3\2\2\2\u00dd\u00df\5\30\r\2"+
		"\u00de\u00e0\7\16\2\2\u00df\u00de\3\2\2\2\u00df\u00e0\3\2\2\2\u00e0\u00e2"+
		"\3\2\2\2\u00e1\u00dd\3\2\2\2\u00e1\u00e2\3\2\2\2\u00e2\u00e3\3\2\2\2\u00e3"+
		"\u00e4\7\f\2\2\u00e4\21\3\2\2\2\u00e5\u00e6\5\30\r\2\u00e6\u00e7\7\16"+
		"\2\2\u00e7\23\3\2\2\2\u00e8\u00eb\7\32\2\2\u00e9\u00eb\5\u008cG\2\u00ea"+
		"\u00e8\3\2\2\2\u00ea\u00e9\3\2\2\2\u00eb\u00ee\3\2\2\2\u00ec\u00ed\7b"+
		"\2\2\u00ed\u00ef\5\u008cG\2\u00ee\u00ec\3\2\2\2\u00ee\u00ef\3\2\2\2\u00ef"+
		"\25\3\2\2\2\u00f0\u00f1\7c\2\2\u00f1\u00f2\7x\2\2\u00f2\27\3\2\2\2\u00f3"+
		"\u00f6\5\u008cG\2\u00f4\u00f5\7b\2\2\u00f5\u00f7\5\u008cG\2\u00f6\u00f4"+
		"\3\2\2\2\u00f6\u00f7\3\2\2\2\u00f7\31\3\2\2\2\u00f8\u00fb\7i\2\2\u00f9"+
		"\u00fc\5\34\17\2\u00fa\u00fc\5\36\20\2\u00fb\u00f9\3\2\2\2\u00fb\u00fa"+
		"\3\2\2\2\u00fc\u00fd\3\2\2\2\u00fd\u00fe\5\u0096L\2\u00fe\u0105\3\2\2"+
		"\2\u00ff\u0100\7i\2\2\u0100\u0101\7\\\2\2\u0101\u0102\5t;\2\u0102\u0103"+
		"\5\u0096L\2\u0103\u0105\3\2\2\2\u0104\u00f8\3\2\2\2\u0104\u00ff\3\2\2"+
		"\2\u0105\33\3\2\2\2\u0106\u0107\5\24\13\2\u0107\u0108\5\26\f\2\u0108\u0109"+
		"\5\u0096L\2\u0109\u0111\3\2\2\2\u010a\u010c\5\20\t\2\u010b\u010d\5\26"+
		"\f\2\u010c\u010b\3\2\2\2\u010c\u010d\3\2\2\2\u010d\u010e\3\2\2\2\u010e"+
		"\u010f\5\u0096L\2\u010f\u0111\3\2\2\2\u0110\u0106\3\2\2\2\u0110\u010a"+
		"\3\2\2\2\u0111\35\3\2\2\2\u0112\u0116\5 \21\2\u0113\u0116\5R*\2\u0114"+
		"\u0116\5P)\2\u0115\u0112\3\2\2\2\u0115\u0113\3\2\2\2\u0115\u0114\3\2\2"+
		"\2\u0116\37\3\2\2\2\u0117\u0118\5\"\22\2\u0118\u0119\5\u0096L\2\u0119"+
		"!\3\2\2\2\u011a\u011b\5.\30\2\u011b\u0120\5$\23\2\u011c\u011d\7\16\2\2"+
		"\u011d\u011f\5$\23\2\u011e\u011c\3\2\2\2\u011f\u0122\3\2\2\2\u0120\u011e"+
		"\3\2\2\2\u0120\u0121\3\2\2\2\u0121#\3\2\2\2\u0122\u0120\3\2\2\2\u0123"+
		"\u0126\5v<\2\u0124\u0125\7\17\2\2\u0125\u0127\5t;\2\u0126\u0124\3\2\2"+
		"\2\u0126\u0127\3\2\2\2\u0127%\3\2\2\2\u0128\u0129\7\r\2\2\u0129\'\3\2"+
		"\2\2\u012a\u012b\6\25\2\2\u012b\u012c\5r:\2\u012c\u012d\5\u0096L\2\u012d"+
		")\3\2\2\2\u012e\u012f\7]\2\2\u012f\u0130\7\t\2\2\u0130\u0131\5r:\2\u0131"+
		"\u0132\7\n\2\2\u0132\u0135\5\6\4\2\u0133\u0134\7M\2\2\u0134\u0136\5\6"+
		"\4\2\u0135\u0133\3\2\2\2\u0135\u0136\3\2\2\2\u0136+\3\2\2\2\u0137\u0138"+
		"\7I\2\2\u0138\u0139\5\6\4\2\u0139\u013a\7W\2\2\u013a\u013b\7\t\2\2\u013b"+
		"\u013c\5r:\2\u013c\u013d\7\n\2\2\u013d\u013e\5\u0096L\2\u013e\u0170\3"+
		"\2\2\2\u013f\u0140\7W\2\2\u0140\u0141\7\t\2\2\u0141\u0142\5r:\2\u0142"+
		"\u0143\7\n\2\2\u0143\u0144\5\6\4\2\u0144\u0170\3\2\2\2\u0145\u0146\7U"+
		"\2\2\u0146\u0149\7\t\2\2\u0147\u014a\5r:\2\u0148\u014a\5\"\22\2\u0149"+
		"\u0147\3\2\2\2\u0149\u0148\3\2\2\2\u0149\u014a\3\2\2\2\u014a\u014b\3\2"+
		"\2\2\u014b\u014d\7\r\2\2\u014c\u014e\5r:\2\u014d\u014c\3\2\2\2\u014d\u014e"+
		"\3\2\2\2\u014e\u014f\3\2\2\2\u014f\u0151\7\r\2\2\u0150\u0152\5r:\2\u0151"+
		"\u0150\3\2\2\2\u0151\u0152\3\2\2\2\u0152\u0153\3\2\2\2\u0153\u0154\7\n"+
		"\2\2\u0154\u0170\5\6\4\2\u0155\u0156\7U\2\2\u0156\u0159\7\t\2\2\u0157"+
		"\u015a\5t;\2\u0158\u015a\5\"\22\2\u0159\u0157\3\2\2\2\u0159\u0158\3\2"+
		"\2\2\u015a\u015b\3\2\2\2\u015b\u015c\7`\2\2\u015c\u015d\5r:\2\u015d\u015e"+
		"\7\n\2\2\u015e\u015f\5\6\4\2\u015f\u0170\3\2\2\2\u0160\u0162\7U\2\2\u0161"+
		"\u0163\7l\2\2\u0162\u0161\3\2\2\2\u0162\u0163\3\2\2\2\u0163\u0164\3\2"+
		"\2\2\u0164\u0167\7\t\2\2\u0165\u0168\5t;\2\u0166\u0168\5\"\22\2\u0167"+
		"\u0165\3\2\2\2\u0167\u0166\3\2\2\2\u0168\u0169\3\2\2\2\u0169\u016a\5\u008e"+
		"H\2\u016a\u016b\6\27\3\2\u016b\u016c\5r:\2\u016c\u016d\7\n\2\2\u016d\u016e"+
		"\5\6\4\2\u016e\u0170\3\2\2\2\u016f\u0137\3\2\2\2\u016f\u013f\3\2\2\2\u016f"+
		"\u0145\3\2\2\2\u016f\u0155\3\2\2\2\u016f\u0160\3\2\2\2\u0170-\3\2\2\2"+
		"\u0171\u0175\7O\2\2\u0172\u0175\5\u0094K\2\u0173\u0175\7h\2\2\u0174\u0171"+
		"\3\2\2\2\u0174\u0172\3\2\2\2\u0174\u0173\3\2\2\2\u0175/\3\2\2\2\u0176"+
		"\u0179\7T\2\2\u0177\u0178\6\31\4\2\u0178\u017a\5\u008eH\2\u0179\u0177"+
		"\3\2\2\2\u0179\u017a\3\2\2\2\u017a\u017b\3\2\2\2\u017b\u017c\5\u0096L"+
		"\2\u017c\61\3\2\2\2\u017d\u0180\7H\2\2\u017e\u017f\6\32\5\2\u017f\u0181"+
		"\5\u008eH\2\u0180\u017e\3\2\2\2\u0180\u0181\3\2\2\2\u0181\u0182\3\2\2"+
		"\2\u0182\u0183\5\u0096L\2\u0183\63\3\2\2\2\u0184\u0187\7R\2\2\u0185\u0186"+
		"\6\33\6\2\u0186\u0188\5r:\2\u0187\u0185\3\2\2\2\u0187\u0188\3\2\2\2\u0188"+
		"\u0189\3\2\2\2\u0189\u018a\5\u0096L\2\u018a\65\3\2\2\2\u018b\u018e\7v"+
		"\2\2\u018c\u018d\6\34\7\2\u018d\u018f\5r:\2\u018e\u018c\3\2\2\2\u018e"+
		"\u018f\3\2\2\2\u018f\u0190\3\2\2\2\u0190\u0191\5\u0096L\2\u0191\67\3\2"+
		"\2\2\u0192\u0193\7[\2\2\u0193\u0194\7\t\2\2\u0194\u0195\5r:\2\u0195\u0196"+
		"\7\n\2\2\u0196\u0197\5\6\4\2\u01979\3\2\2\2\u0198\u0199\7V\2\2\u0199\u019a"+
		"\7\t\2\2\u019a\u019b\5r:\2\u019b\u019c\7\n\2\2\u019c\u019d\5<\37\2\u019d"+
		";\3\2\2\2\u019e\u01a0\7\13\2\2\u019f\u01a1\5> \2\u01a0\u019f\3\2\2\2\u01a0"+
		"\u01a1\3\2\2\2\u01a1\u01a6\3\2\2\2\u01a2\u01a4\5B\"\2\u01a3\u01a5\5> "+
		"\2\u01a4\u01a3\3\2\2\2\u01a4\u01a5\3\2\2\2\u01a5\u01a7\3\2\2\2\u01a6\u01a2"+
		"\3\2\2\2\u01a6\u01a7\3\2\2\2\u01a7\u01a8\3\2\2\2\u01a8\u01a9\7\f\2\2\u01a9"+
		"=\3\2\2\2\u01aa\u01ac\5@!\2\u01ab\u01aa\3\2\2\2\u01ac\u01ad\3\2\2\2\u01ad"+
		"\u01ab\3\2\2\2\u01ad\u01ae\3\2\2\2\u01ae?\3\2\2\2\u01af\u01b0\7L\2\2\u01b0"+
		"\u01b1\5r:\2\u01b1\u01b3\7\21\2\2\u01b2\u01b4\5\n\6\2\u01b3\u01b2\3\2"+
		"\2\2\u01b3\u01b4\3\2\2\2\u01b4A\3\2\2\2\u01b5\u01b6\7\\\2\2\u01b6\u01b8"+
		"\7\21\2\2\u01b7\u01b9\5\n\6\2\u01b8\u01b7\3\2\2\2\u01b8\u01b9\3\2\2\2"+
		"\u01b9C\3\2\2\2\u01ba\u01bb\5\u008eH\2\u01bb\u01bc\7\21\2\2\u01bc\u01bd"+
		"\5\6\4\2\u01bdE\3\2\2\2\u01be\u01bf\7^\2\2\u01bf\u01c0\6$\b\2\u01c0\u01c1"+
		"\5r:\2\u01c1\u01c2\5\u0096L\2\u01c2G\3\2\2\2\u01c3\u01c4\7a\2\2\u01c4"+
		"\u01ca\5\b\5\2\u01c5\u01c7\5J&\2\u01c6\u01c8\5L\'\2\u01c7\u01c6\3\2\2"+
		"\2\u01c7\u01c8\3\2\2\2\u01c8\u01cb\3\2\2\2\u01c9\u01cb\5L\'\2\u01ca\u01c5"+
		"\3\2\2\2\u01ca\u01c9\3\2\2\2\u01cbI\3\2\2\2\u01cc\u01d2\7P\2\2\u01cd\u01cf"+
		"\7\t\2\2\u01ce\u01d0\5v<\2\u01cf\u01ce\3\2\2\2\u01cf\u01d0\3\2\2\2\u01d0"+
		"\u01d1\3\2\2\2\u01d1\u01d3\7\n\2\2\u01d2\u01cd\3\2\2\2\u01d2\u01d3\3\2"+
		"\2\2\u01d3\u01d4\3\2\2\2\u01d4\u01d5\5\b\5\2\u01d5K\3\2\2\2\u01d6\u01d7"+
		"\7Q\2\2\u01d7\u01d8\5\b\5\2\u01d8M\3\2\2\2\u01d9\u01da\7X\2\2\u01da\u01db"+
		"\5\u0096L\2\u01dbO\3\2\2\2\u01dc\u01de\7k\2\2\u01dd\u01dc\3\2\2\2\u01dd"+
		"\u01de\3\2\2\2\u01de\u01df\3\2\2\2\u01df\u01e1\7Y\2\2\u01e0\u01e2\7\32"+
		"\2\2\u01e1\u01e0\3\2\2\2\u01e1\u01e2\3\2\2\2\u01e2\u01e3\3\2\2\2\u01e3"+
		"\u01e4\5\u008eH\2\u01e4\u01e6\7\t\2\2\u01e5\u01e7\5Z.\2\u01e6\u01e5\3"+
		"\2\2\2\u01e6\u01e7\3\2\2\2\u01e7\u01e8\3\2\2\2\u01e8\u01e9\7\n\2\2\u01e9"+
		"\u01ea\7\13\2\2\u01ea\u01eb\5`\61\2\u01eb\u01ec\7\f\2\2\u01ecQ\3\2\2\2"+
		"\u01ed\u01ee\7d\2\2\u01ee\u01ef\5\u008eH\2\u01ef\u01f0\5T+\2\u01f0S\3"+
		"\2\2\2\u01f1\u01f2\7f\2\2\u01f2\u01f4\5t;\2\u01f3\u01f1\3\2\2\2\u01f3"+
		"\u01f4\3\2\2\2\u01f4\u01f5\3\2\2\2\u01f5\u01f9\7\13\2\2\u01f6\u01f8\5"+
		"V,\2\u01f7\u01f6\3\2\2\2\u01f8\u01fb\3\2\2\2\u01f9\u01f7\3\2\2\2\u01f9"+
		"\u01fa\3\2\2\2\u01fa\u01fc\3\2\2\2\u01fb\u01f9\3\2\2\2\u01fc\u01fd\7\f"+
		"\2\2\u01fdU\3\2\2\2\u01fe\u0203\7u\2\2\u01ff\u0200\6,\t\2\u0200\u0203"+
		"\5\u008eH\2\u0201\u0203\7k\2\2\u0202\u01fe\3\2\2\2\u0202\u01ff\3\2\2\2"+
		"\u0202\u0201\3\2\2\2\u0203\u0206\3\2\2\2\u0204\u0202\3\2\2\2\u0204\u0205"+
		"\3\2\2\2\u0205\u020d\3\2\2\2\u0206\u0204\3\2\2\2\u0207\u020e\5X-\2\u0208"+
		"\u0209\5v<\2\u0209\u020a\7\17\2\2\u020a\u020b\5x=\2\u020b\u020c\7\r\2"+
		"\2\u020c\u020e\3\2\2\2\u020d\u0207\3\2\2\2\u020d\u0208\3\2\2\2\u020e\u0218"+
		"\3\2\2\2\u020f\u0218\5&\24\2\u0210\u0212\7\37\2\2\u0211\u0210\3\2\2\2"+
		"\u0211\u0212\3\2\2\2\u0212\u0213\3\2\2\2\u0213\u0214\5l\67\2\u0214\u0215"+
		"\7\17\2\2\u0215\u0216\5t;\2\u0216\u0218\3\2\2\2\u0217\u0204\3\2\2\2\u0217"+
		"\u020f\3\2\2\2\u0217\u0211\3\2\2\2\u0218W\3\2\2\2\u0219\u021b\7\32\2\2"+
		"\u021a\u0219\3\2\2\2\u021a\u021b\3\2\2\2\u021b\u021d\3\2\2\2\u021c\u021e"+
		"\7\37\2\2\u021d\u021c\3\2\2\2\u021d\u021e\3\2\2\2\u021e\u021f\3\2\2\2"+
		"\u021f\u0220\5l\67\2\u0220\u0222\7\t\2\2\u0221\u0223\5Z.\2\u0222\u0221"+
		"\3\2\2\2\u0222\u0223\3\2\2\2\u0223\u0224\3\2\2\2\u0224\u0225\7\n\2\2\u0225"+
		"\u0226\7\13\2\2\u0226\u0227\5`\61\2\u0227\u0228\7\f\2\2\u0228\u0247\3"+
		"\2\2\2\u0229\u022b\7\32\2\2\u022a\u0229\3\2\2\2\u022a\u022b\3\2\2\2\u022b"+
		"\u022d\3\2\2\2\u022c\u022e\7\37\2\2\u022d\u022c\3\2\2\2\u022d\u022e\3"+
		"\2\2\2\u022e\u022f\3\2\2\2\u022f\u0230\5\u0088E\2\u0230\u0231\7\t\2\2"+
		"\u0231\u0232\7\n\2\2\u0232\u0233\7\13\2\2\u0233\u0234\5`\61\2\u0234\u0235"+
		"\7\f\2\2\u0235\u0247\3\2\2\2\u0236\u0238\7\32\2\2\u0237\u0236\3\2\2\2"+
		"\u0237\u0238\3\2\2\2\u0238\u023a\3\2\2\2\u0239\u023b\7\37\2\2\u023a\u0239"+
		"\3\2\2\2\u023a\u023b\3\2\2\2\u023b\u023c\3\2\2\2\u023c\u023d\5\u008aF"+
		"\2\u023d\u023f\7\t\2\2\u023e\u0240\5Z.\2\u023f\u023e\3\2\2\2\u023f\u0240"+
		"\3\2\2\2\u0240\u0241\3\2\2\2\u0241\u0242\7\n\2\2\u0242\u0243\7\13\2\2"+
		"\u0243\u0244\5`\61\2\u0244\u0245\7\f\2\2\u0245\u0247\3\2\2\2\u0246\u021a"+
		"\3\2\2\2\u0246\u022a\3\2\2\2\u0246\u0237\3\2\2\2\u0247Y\3\2\2\2\u0248"+
		"\u024d\5\\/\2\u0249\u024a\7\16\2\2\u024a\u024c\5\\/\2\u024b\u0249\3\2"+
		"\2\2\u024c\u024f\3\2\2\2\u024d\u024b\3\2\2\2\u024d\u024e\3\2\2\2\u024e"+
		"\u0252\3\2\2\2\u024f\u024d\3\2\2\2\u0250\u0251\7\16\2\2\u0251\u0253\5"+
		"^\60\2\u0252\u0250\3\2\2\2\u0252\u0253\3\2\2\2\u0253\u0256\3\2\2\2\u0254"+
		"\u0256\5^\60\2\u0255\u0248\3\2\2\2\u0255\u0254\3\2\2\2\u0256[\3\2\2\2"+
		"\u0257\u025a\5v<\2\u0258\u0259\7\17\2\2\u0259\u025b\5t;\2\u025a\u0258"+
		"\3\2\2\2\u025a\u025b\3\2\2\2\u025b]\3\2\2\2\u025c\u025d\7\22\2\2\u025d"+
		"\u025e\5t;\2\u025e_\3\2\2\2\u025f\u0261\5b\62\2\u0260\u025f\3\2\2\2\u0260"+
		"\u0261\3\2\2\2\u0261a\3\2\2\2\u0262\u0264\5\4\3\2\u0263\u0262\3\2\2\2"+
		"\u0264\u0265\3\2\2\2\u0265\u0263\3\2\2\2\u0265\u0266\3\2\2\2\u0266c\3"+
		"\2\2\2\u0267\u0268\7\7\2\2\u0268\u0269\5f\64\2\u0269\u026a\7\b\2\2\u026a"+
		"e\3\2\2\2\u026b\u026d\7\16\2\2\u026c\u026b\3\2\2\2\u026d\u0270\3\2\2\2"+
		"\u026e\u026c\3\2\2\2\u026e\u026f\3\2\2\2\u026f\u0272\3\2\2\2\u0270\u026e"+
		"\3\2\2\2\u0271\u0273\5h\65\2\u0272\u0271\3\2\2\2\u0272\u0273\3\2\2\2\u0273"+
		"\u027c\3\2\2\2\u0274\u0276\7\16\2\2\u0275\u0274\3\2\2\2\u0276\u0277\3"+
		"\2\2\2\u0277\u0275\3\2\2\2\u0277\u0278\3\2\2\2\u0278\u0279\3\2\2\2\u0279"+
		"\u027b\5h\65\2\u027a\u0275\3\2\2\2\u027b\u027e\3\2\2\2\u027c\u027a\3\2"+
		"\2\2\u027c\u027d\3\2\2\2\u027d\u0282\3\2\2\2\u027e\u027c\3\2\2\2\u027f"+
		"\u0281\7\16\2\2\u0280\u027f\3\2\2\2\u0281\u0284\3\2\2\2\u0282\u0280\3"+
		"\2\2\2\u0282\u0283\3\2\2\2\u0283g\3\2\2\2\u0284\u0282\3\2\2\2\u0285\u0287"+
		"\7\22\2\2\u0286\u0285\3\2\2\2\u0286\u0287\3\2\2\2\u0287\u0288\3\2\2\2"+
		"\u0288\u0289\5t;\2\u0289i\3\2\2\2\u028a\u028b\5l\67\2\u028b\u028c\7\21"+
		"\2\2\u028c\u028d\5t;\2\u028d\u02b8\3\2\2\2\u028e\u028f\7\7\2\2\u028f\u0290"+
		"\5t;\2\u0290\u0291\7\b\2\2\u0291\u0292\7\21\2\2\u0292\u0293\5t;\2\u0293"+
		"\u02b8\3\2\2\2\u0294\u0296\7k\2\2\u0295\u0294\3\2\2\2\u0295\u0296\3\2"+
		"\2\2\u0296\u0298\3\2\2\2\u0297\u0299\7\32\2\2\u0298\u0297\3\2\2\2\u0298"+
		"\u0299\3\2\2\2\u0299\u029a\3\2\2\2\u029a\u029b\5l\67\2\u029b\u029d\7\t"+
		"\2\2\u029c\u029e\5Z.\2\u029d\u029c\3\2\2\2\u029d\u029e\3\2\2\2\u029e\u029f"+
		"\3\2\2\2\u029f\u02a0\7\n\2\2\u02a0\u02a1\7\13\2\2\u02a1\u02a2\5`\61\2"+
		"\u02a2\u02a3\7\f\2\2\u02a3\u02b8\3\2\2\2\u02a4\u02a5\5\u0088E\2\u02a5"+
		"\u02a6\7\t\2\2\u02a6\u02a7\7\n\2\2\u02a7\u02a8\7\13\2\2\u02a8\u02a9\5"+
		"`\61\2\u02a9\u02aa\7\f\2\2\u02aa\u02b8\3\2\2\2\u02ab\u02ac\5\u008aF\2"+
		"\u02ac\u02ad\7\t\2\2\u02ad\u02ae\5\\/\2\u02ae\u02af\7\n\2\2\u02af\u02b0"+
		"\7\13\2\2\u02b0\u02b1\5`\61\2\u02b1\u02b2\7\f\2\2\u02b2\u02b8\3\2\2\2"+
		"\u02b3\u02b5\7\22\2\2\u02b4\u02b3\3\2\2\2\u02b4\u02b5\3\2\2\2\u02b5\u02b6"+
		"\3\2\2\2\u02b6\u02b8\5t;\2\u02b7\u028a\3\2\2\2\u02b7\u028e\3\2\2\2\u02b7"+
		"\u0295\3\2\2\2\u02b7\u02a4\3\2\2\2\u02b7\u02ab\3\2\2\2\u02b7\u02b4\3\2"+
		"\2\2\u02b8k\3\2\2\2\u02b9\u02c1\5\u008cG\2\u02ba\u02c1\7x\2\2\u02bb\u02c1"+
		"\5\u0084C\2\u02bc\u02bd\7\7\2\2\u02bd\u02be\5t;\2\u02be\u02bf\7\b\2\2"+
		"\u02bf\u02c1\3\2\2\2\u02c0\u02b9\3\2\2\2\u02c0\u02ba\3\2\2\2\u02c0\u02bb"+
		"\3\2\2\2\u02c0\u02bc\3\2\2\2\u02c1m\3\2\2\2\u02c2\u02ce\7\t\2\2\u02c3"+
		"\u02c8\5p9\2\u02c4\u02c5\7\16\2\2\u02c5\u02c7\5p9\2\u02c6\u02c4\3\2\2"+
		"\2\u02c7\u02ca\3\2\2\2\u02c8\u02c6\3\2\2\2\u02c8\u02c9\3\2\2\2\u02c9\u02cc"+
		"\3\2\2\2\u02ca\u02c8\3\2\2\2\u02cb\u02cd\7\16\2\2\u02cc\u02cb\3\2\2\2"+
		"\u02cc\u02cd\3\2\2\2\u02cd\u02cf\3\2\2\2\u02ce\u02c3\3\2\2\2\u02ce\u02cf"+
		"\3\2\2\2\u02cf\u02d0\3\2\2\2\u02d0\u02d1\7\n\2\2\u02d1o\3\2\2\2\u02d2"+
		"\u02d4\7\22\2\2\u02d3\u02d2\3\2\2\2\u02d3\u02d4\3\2\2\2\u02d4\u02d7\3"+
		"\2\2\2\u02d5\u02d8\5t;\2\u02d6\u02d8\5\u008eH\2\u02d7\u02d5\3\2\2\2\u02d7"+
		"\u02d6\3\2\2\2\u02d8q\3\2\2\2\u02d9\u02de\5t;\2\u02da\u02db\7\16\2\2\u02db"+
		"\u02dd\5t;\2\u02dc\u02da\3\2\2\2\u02dd\u02e0\3\2\2\2\u02de\u02dc\3\2\2"+
		"\2\u02de\u02df\3\2\2\2\u02dfs\3\2\2\2\u02e0\u02de\3\2\2\2\u02e1\u02e2"+
		"\b;\1\2\u02e2\u0315\5z>\2\u02e3\u02e5\7d\2\2\u02e4\u02e6\5\u008eH\2\u02e5"+
		"\u02e4\3\2\2\2\u02e5\u02e6\3\2\2\2\u02e6\u02e7\3\2\2\2\u02e7\u0315\5T"+
		"+\2\u02e8\u02e9\7N\2\2\u02e9\u02eb\5t;\2\u02ea\u02ec\5n8\2\u02eb\u02ea"+
		"\3\2\2\2\u02eb\u02ec\3\2\2\2\u02ec\u0315\3\2\2\2\u02ed\u02ee\7N\2\2\u02ee"+
		"\u02ef\7\23\2\2\u02ef\u0315\5\u008eH\2\u02f0\u02f1\7_\2\2\u02f1\u0315"+
		"\5t;\'\u02f2\u02f3\7S\2\2\u02f3\u0315\5t;&\u02f4\u02f5\7K\2\2\u02f5\u0315"+
		"\5t;%\u02f6\u02f7\7\24\2\2\u02f7\u0315\5t;$\u02f8\u02f9\7\25\2\2\u02f9"+
		"\u0315\5t;#\u02fa\u02fb\7\26\2\2\u02fb\u0315\5t;\"\u02fc\u02fd\7\27\2"+
		"\2\u02fd\u0315\5t;!\u02fe\u02ff\7\30\2\2\u02ff\u0315\5t; \u0300\u0301"+
		"\7\31\2\2\u0301\u0315\5t;\37\u0302\u0303\7l\2\2\u0303\u0315\5t;\36\u0304"+
		"\u0305\7j\2\2\u0305\u0306\7\t\2\2\u0306\u0307\5t;\2\u0307\u0308\7\n\2"+
		"\2\u0308\u0315\3\2\2\2\u0309\u0315\5\66\34\2\u030a\u0315\7Z\2\2\u030b"+
		"\u0315\5\u008eH\2\u030c\u0315\7g\2\2\u030d\u0315\5\u0082B\2\u030e\u0315"+
		"\5d\63\2\u030f\u0315\5x=\2\u0310\u0311\7\t\2\2\u0311\u0312\5r:\2\u0312"+
		"\u0313\7\n\2\2\u0313\u0315\3\2\2\2\u0314\u02e1\3\2\2\2\u0314\u02e3\3\2"+
		"\2\2\u0314\u02e8\3\2\2\2\u0314\u02ed\3\2\2\2\u0314\u02f0\3\2\2\2\u0314"+
		"\u02f2\3\2\2\2\u0314\u02f4\3\2\2\2\u0314\u02f6\3\2\2\2\u0314\u02f8\3\2"+
		"\2\2\u0314\u02fa\3\2\2\2\u0314\u02fc\3\2\2\2\u0314\u02fe\3\2\2\2\u0314"+
		"\u0300\3\2\2\2\u0314\u0302\3\2\2\2\u0314\u0304\3\2\2\2\u0314\u0309\3\2"+
		"\2\2\u0314\u030a\3\2\2\2\u0314\u030b\3\2\2\2\u0314\u030c\3\2\2\2\u0314"+
		"\u030d\3\2\2\2\u0314\u030e\3\2\2\2\u0314\u030f\3\2\2\2\u0314\u0310\3\2"+
		"\2\2\u0315\u0367\3\2\2\2\u0316\u0317\f\35\2\2\u0317\u0318\7\35\2\2\u0318"+
		"\u0366\5t;\35\u0319\u031a\f\34\2\2\u031a\u031b\t\2\2\2\u031b\u0366\5t"+
		";\35\u031c\u031d\f\33\2\2\u031d\u031e\t\3\2\2\u031e\u0366\5t;\34\u031f"+
		"\u0320\f\32\2\2\u0320\u0321\7\36\2\2\u0321\u0366\5t;\33\u0322\u0323\f"+
		"\31\2\2\u0323\u0324\t\4\2\2\u0324\u0366\5t;\32\u0325\u0326\f\30\2\2\u0326"+
		"\u0327\t\5\2\2\u0327\u0366\5t;\31\u0328\u0329\f\27\2\2\u0329\u032a\7J"+
		"\2\2\u032a\u0366\5t;\30\u032b\u032c\f\26\2\2\u032c\u032d\7`\2\2\u032d"+
		"\u0366\5t;\27\u032e\u032f\f\25\2\2\u032f\u0330\t\6\2\2\u0330\u0366\5t"+
		";\26\u0331\u0332\f\24\2\2\u0332\u0333\7+\2\2\u0333\u0366\5t;\25\u0334"+
		"\u0335\f\23\2\2\u0335\u0336\7,\2\2\u0336\u0366\5t;\24\u0337\u0338\f\22"+
		"\2\2\u0338\u0339\7-\2\2\u0339\u0366\5t;\23\u033a\u033b\f\21\2\2\u033b"+
		"\u033c\7.\2\2\u033c\u0366\5t;\22\u033d\u033e\f\20\2\2\u033e\u033f\7/\2"+
		"\2\u033f\u0366\5t;\21\u0340\u0341\f\17\2\2\u0341\u0342\7\20\2\2\u0342"+
		"\u0343\5t;\2\u0343\u0344\7\21\2\2\u0344\u0345\5t;\20\u0345\u0366\3\2\2"+
		"\2\u0346\u0347\f\16\2\2\u0347\u0348\7\17\2\2\u0348\u0366\5t;\16\u0349"+
		"\u034a\f\r\2\2\u034a\u034b\5\u0080A\2\u034b\u034c\5t;\r\u034c\u0366\3"+
		"\2\2\2\u034d\u034e\f.\2\2\u034e\u034f\7\7\2\2\u034f\u0350\5r:\2\u0350"+
		"\u0351\7\b\2\2\u0351\u0366\3\2\2\2\u0352\u0354\f-\2\2\u0353\u0355\7\20"+
		"\2\2\u0354\u0353\3\2\2\2\u0354\u0355\3\2\2\2\u0355\u0356\3\2\2\2\u0356"+
		"\u0358\7\23\2\2\u0357\u0359\7\37\2\2\u0358\u0357\3\2\2\2\u0358\u0359\3"+
		"\2\2\2\u0359\u035a\3\2\2\2\u035a\u0366\5\u008cG\2\u035b\u035c\f,\2\2\u035c"+
		"\u0366\5n8\2\u035d\u035e\f)\2\2\u035e\u035f\6;\37\2\u035f\u0366\7\24\2"+
		"\2\u0360\u0361\f(\2\2\u0361\u0362\6;!\2\u0362\u0366\7\25\2\2\u0363\u0364"+
		"\f\13\2\2\u0364\u0366\7y\2\2\u0365\u0316\3\2\2\2\u0365\u0319\3\2\2\2\u0365"+
		"\u031c\3\2\2\2\u0365\u031f\3\2\2\2\u0365\u0322\3\2\2\2\u0365\u0325\3\2"+
		"\2\2\u0365\u0328\3\2\2\2\u0365\u032b\3\2\2\2\u0365\u032e\3\2\2\2\u0365"+
		"\u0331\3\2\2\2\u0365\u0334\3\2\2\2\u0365\u0337\3\2\2\2\u0365\u033a\3\2"+
		"\2\2\u0365\u033d\3\2\2\2\u0365\u0340\3\2\2\2\u0365\u0346\3\2\2\2\u0365"+
		"\u0349\3\2\2\2\u0365\u034d\3\2\2\2\u0365\u0352\3\2\2\2\u0365\u035b\3\2"+
		"\2\2\u0365\u035d\3\2\2\2\u0365\u0360\3\2\2\2\u0365\u0363\3\2\2\2\u0366"+
		"\u0369\3\2\2\2\u0367\u0365\3\2\2\2\u0367\u0368\3\2\2\2\u0368u\3\2\2\2"+
		"\u0369\u0367\3\2\2\2\u036a\u036e\5\u008eH\2\u036b\u036e\5d\63\2\u036c"+
		"\u036e\5x=\2\u036d\u036a\3\2\2\2\u036d\u036b\3\2\2\2\u036d\u036c\3\2\2"+
		"\2\u036ew\3\2\2\2\u036f\u0378\7\13\2\2\u0370\u0375\5j\66\2\u0371\u0372"+
		"\7\16\2\2\u0372\u0374\5j\66\2\u0373\u0371\3\2\2\2\u0374\u0377\3\2\2\2"+
		"\u0375\u0373\3\2\2\2\u0375\u0376\3\2\2\2\u0376\u0379\3\2\2\2\u0377\u0375"+
		"\3\2\2\2\u0378\u0370\3\2\2\2\u0378\u0379\3\2\2\2\u0379\u037b\3\2\2\2\u037a"+
		"\u037c\7\16\2\2\u037b\u037a\3\2\2\2\u037b\u037c\3\2\2\2\u037c\u037d\3"+
		"\2\2\2\u037d\u037e\7\f\2\2\u037ey\3\2\2\2\u037f\u0398\5P)\2\u0380\u0382"+
		"\7k\2\2\u0381\u0380\3\2\2\2\u0381\u0382\3\2\2\2\u0382\u0383\3\2\2\2\u0383"+
		"\u0385\7Y\2\2\u0384\u0386\7\32\2\2\u0385\u0384\3\2\2\2\u0385\u0386\3\2"+
		"\2\2\u0386\u0387\3\2\2\2\u0387\u0389\7\t\2\2\u0388\u038a\5Z.\2\u0389\u0388"+
		"\3\2\2\2\u0389\u038a\3\2\2\2\u038a\u038b\3\2\2\2\u038b\u038c\7\n\2\2\u038c"+
		"\u038d\7\13\2\2\u038d\u038e\5`\61\2\u038e\u038f\7\f\2\2\u038f\u0398\3"+
		"\2\2\2\u0390\u0392\7k\2\2\u0391\u0390\3\2\2\2\u0391\u0392\3\2\2\2\u0392"+
		"\u0393\3\2\2\2\u0393\u0394\5|?\2\u0394\u0395\7<\2\2\u0395\u0396\5~@\2"+
		"\u0396\u0398\3\2\2\2\u0397\u037f\3\2\2\2\u0397\u0381\3\2\2\2\u0397\u0391"+
		"\3\2\2\2\u0398{\3\2\2\2\u0399\u03a0\5\u008eH\2\u039a\u039c\7\t\2\2\u039b"+
		"\u039d\5Z.\2\u039c\u039b\3\2\2\2\u039c\u039d\3\2\2\2\u039d\u039e\3\2\2"+
		"\2\u039e\u03a0\7\n\2\2\u039f\u0399\3\2\2\2\u039f\u039a\3\2\2\2\u03a0}"+
		"\3\2\2\2\u03a1\u03a7\5t;\2\u03a2\u03a3\7\13\2\2\u03a3\u03a4\5`\61\2\u03a4"+
		"\u03a5\7\f\2\2\u03a5\u03a7\3\2\2\2\u03a6\u03a1\3\2\2\2\u03a6\u03a2\3\2"+
		"\2\2\u03a7\177\3\2\2\2\u03a8\u03a9\t\7\2\2\u03a9\u0081\3\2\2\2\u03aa\u03b2"+
		"\7=\2\2\u03ab\u03b2\7>\2\2\u03ac\u03b2\7x\2\2\u03ad\u03b2\7y\2\2\u03ae"+
		"\u03b2\7\6\2\2\u03af\u03b2\5\u0084C\2\u03b0\u03b2\5\u0086D\2\u03b1\u03aa"+
		"\3\2\2\2\u03b1\u03ab\3\2\2\2\u03b1\u03ac\3\2\2\2\u03b1\u03ad\3\2\2\2\u03b1"+
		"\u03ae\3\2\2\2\u03b1\u03af\3\2\2\2\u03b1\u03b0\3\2\2\2\u03b2\u0083\3\2"+
		"\2\2\u03b3\u03b4\t\b\2\2\u03b4\u0085\3\2\2\2\u03b5\u03b6\t\t\2\2\u03b6"+
		"\u0087\3\2\2\2\u03b7\u03b8\6E#\2\u03b8\u03b9\5\u008eH\2\u03b9\u03ba\5"+
		"l\67\2\u03ba\u0089\3\2\2\2\u03bb\u03bc\6F$\2\u03bc\u03bd\5\u008eH\2\u03bd"+
		"\u03be\5l\67\2\u03be\u008b\3\2\2\2\u03bf\u03c2\5\u008eH\2\u03c0\u03c2"+
		"\5\u0090I\2\u03c1\u03bf\3\2\2\2\u03c1\u03c0\3\2\2\2\u03c2\u008d\3\2\2"+
		"\2\u03c3\u03c4\t\n\2\2\u03c4\u008f\3\2\2\2\u03c5\u03c9\5\u0092J\2\u03c6"+
		"\u03c9\7=\2\2\u03c7\u03c9\7>\2\2\u03c8\u03c5\3\2\2\2\u03c8\u03c6\3\2\2"+
		"\2\u03c8\u03c7\3\2\2\2\u03c9\u0091\3\2\2\2\u03ca\u03f9\7H\2\2\u03cb\u03f9"+
		"\7I\2\2\u03cc\u03f9\7J\2\2\u03cd\u03f9\7K\2\2\u03ce\u03f9\7L\2\2\u03cf"+
		"\u03f9\7M\2\2\u03d0\u03f9\7N\2\2\u03d1\u03f9\7O\2\2\u03d2\u03f9\7P\2\2"+
		"\u03d3\u03f9\7Q\2\2\u03d4\u03f9\7R\2\2\u03d5\u03f9\7S\2\2\u03d6\u03f9"+
		"\7T\2\2\u03d7\u03f9\7U\2\2\u03d8\u03f9\7V\2\2\u03d9\u03f9\7W\2\2\u03da"+
		"\u03f9\7X\2\2\u03db\u03f9\7Y\2\2\u03dc\u03f9\7Z\2\2\u03dd\u03f9\7[\2\2"+
		"\u03de\u03f9\7\\\2\2\u03df\u03f9\7]\2\2\u03e0\u03f9\7^\2\2\u03e1\u03f9"+
		"\7_\2\2\u03e2\u03f9\7`\2\2\u03e3\u03f9\7a\2\2\u03e4\u03f9\7d\2\2\u03e5"+
		"\u03f9\7e\2\2\u03e6\u03f9\7f\2\2\u03e7\u03f9\7g\2\2\u03e8\u03f9\7h\2\2"+
		"\u03e9\u03f9\7i\2\2\u03ea\u03f9\7j\2\2\u03eb\u03f9\7m\2\2\u03ec\u03f9"+
		"\5\u0094K\2\u03ed\u03f9\7p\2\2\u03ee\u03f9\7q\2\2\u03ef\u03f9\7r\2\2\u03f0"+
		"\u03f9\7s\2\2\u03f1\u03f9\7t\2\2\u03f2\u03f9\7u\2\2\u03f3\u03f9\7v\2\2"+
		"\u03f4\u03f9\7k\2\2\u03f5\u03f9\7l\2\2\u03f6\u03f9\7c\2\2\u03f7\u03f9"+
		"\7b\2\2\u03f8\u03ca\3\2\2\2\u03f8\u03cb\3\2\2\2\u03f8\u03cc\3\2\2\2\u03f8"+
		"\u03cd\3\2\2\2\u03f8\u03ce\3\2\2\2\u03f8\u03cf\3\2\2\2\u03f8\u03d0\3\2"+
		"\2\2\u03f8\u03d1\3\2\2\2\u03f8\u03d2\3\2\2\2\u03f8\u03d3\3\2\2\2\u03f8"+
		"\u03d4\3\2\2\2\u03f8\u03d5\3\2\2\2\u03f8\u03d6\3\2\2\2\u03f8\u03d7\3\2"+
		"\2\2\u03f8\u03d8\3\2\2\2\u03f8\u03d9\3\2\2\2\u03f8\u03da\3\2\2\2\u03f8"+
		"\u03db\3\2\2\2\u03f8\u03dc\3\2\2\2\u03f8\u03dd\3\2\2\2\u03f8\u03de\3\2"+
		"\2\2\u03f8\u03df\3\2\2\2\u03f8\u03e0\3\2\2\2\u03f8\u03e1\3\2\2\2\u03f8"+
		"\u03e2\3\2\2\2\u03f8\u03e3\3\2\2\2\u03f8\u03e4\3\2\2\2\u03f8\u03e5\3\2"+
		"\2\2\u03f8\u03e6\3\2\2\2\u03f8\u03e7\3\2\2\2\u03f8\u03e8\3\2\2\2\u03f8"+
		"\u03e9\3\2\2\2\u03f8\u03ea\3\2\2\2\u03f8\u03eb\3\2\2\2\u03f8\u03ec\3\2"+
		"\2\2\u03f8\u03ed\3\2\2\2\u03f8\u03ee\3\2\2\2\u03f8\u03ef\3\2\2\2\u03f8"+
		"\u03f0\3\2\2\2\u03f8\u03f1\3\2\2\2\u03f8\u03f2\3\2\2\2\u03f8\u03f3\3\2"+
		"\2\2\u03f8\u03f4\3\2\2\2\u03f8\u03f5\3\2\2\2\u03f8\u03f6\3\2\2\2\u03f8"+
		"\u03f7\3\2\2\2\u03f9\u0093\3\2\2\2\u03fa\u03fb\t\13\2\2\u03fb\u0095\3"+
		"\2\2\2\u03fc\u0401\7\r\2\2\u03fd\u0401\7\2\2\3\u03fe\u0401\6L%\2\u03ff"+
		"\u0401\6L&\2\u0400\u03fc\3\2\2\2\u0400\u03fd\3\2\2\2\u0400\u03fe\3\2\2"+
		"\2\u0400\u03ff\3\2\2\2\u0401\u0097\3\2\2\2q\u0099\u009c\u00b6\u00ba\u00c1"+
		"\u00c7\u00cb\u00d2\u00da\u00df\u00e1\u00ea\u00ee\u00f6\u00fb\u0104\u010c"+
		"\u0110\u0115\u0120\u0126\u0135\u0149\u014d\u0151\u0159\u0162\u0167\u016f"+
		"\u0174\u0179\u0180\u0187\u018e\u01a0\u01a4\u01a6\u01ad\u01b3\u01b8\u01c7"+
		"\u01ca\u01cf\u01d2\u01dd\u01e1\u01e6\u01f3\u01f9\u0202\u0204\u020d\u0211"+
		"\u0217\u021a\u021d\u0222\u022a\u022d\u0237\u023a\u023f\u0246\u024d\u0252"+
		"\u0255\u025a\u0260\u0265\u026e\u0272\u0277\u027c\u0282\u0286\u0295\u0298"+
		"\u029d\u02b4\u02b7\u02c0\u02c8\u02cc\u02ce\u02d3\u02d7\u02de\u02e5\u02eb"+
		"\u0314\u0354\u0358\u0365\u0367\u036d\u0375\u0378\u037b\u0381\u0385\u0389"+
		"\u0391\u0397\u039c\u039f\u03a6\u03b1\u03c1\u03c8\u03f8\u0400";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}