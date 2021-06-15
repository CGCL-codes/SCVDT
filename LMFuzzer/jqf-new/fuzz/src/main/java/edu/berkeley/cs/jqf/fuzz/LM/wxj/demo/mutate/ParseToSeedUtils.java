package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate;

import edu.berkeley.cs.jqf.fuzz.LM.antlr4.main.resources.JavaScriptLexer;
import edu.berkeley.cs.jqf.fuzz.LM.antlr4.main.resources.JavaScriptParser;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeGet;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeNode;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

public class ParseToSeedUtils {

    public ParseToSeedUtils() {
    };

    public  static  Seed ParseToSeed(String fileName) throws IOException {

        CharStream input = CharStreams.fromFileName(fileName);
        // 构造词法分析器
        JavaScriptLexer lexer = new JavaScriptLexer(input);

        CommonTokenStream tokens = new CommonTokenStream(lexer);
        // 实例化解析器
        JavaScriptParser parser = new JavaScriptParser(tokens);
//
        ParseTree tree = parser.program();
        TreeNode  root = TreeGet.getTree(tree,parser);

        return  new Seed(root);
    }


}
