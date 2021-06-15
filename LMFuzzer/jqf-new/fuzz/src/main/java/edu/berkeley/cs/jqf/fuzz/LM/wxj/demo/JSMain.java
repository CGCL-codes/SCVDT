package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo;





import edu.berkeley.cs.jqf.fuzz.LM.antlr4.main.resources.JavaScriptLexer;
import edu.berkeley.cs.jqf.fuzz.LM.antlr4.main.resources.JavaScriptParser;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.ngram.Model;


import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.tree.ParseTree;


import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class JSMain {
    public static void main(String[] args) throws IOException {


        File modelfile = new File(JSMain.class.getClassLoader().getResource("model/tree.arpa").getPath());

        FileReader fileReader = new FileReader(modelfile);

        Model Model = new Model(fileReader);



        CharStream input = CharStreams.fromString("var x =1; var y=x+2;");
        CharStream input2 = CharStreams.fromString("x=true;\n" +
                "Number(x);");
//        CharStream input2 = CharStreams.fromString("var http = require('http'),\n" +
//                "\tfs = require('fs');\n" +
//                "\n" +
//                "// Create an HTTP server\n" +
//                "var httpSrv = http.createServer(function (req, res) {\n" +
//                "\tconsole.log(\"req.url\", req.url);\n" +
//                "\tRouteManager.findRoute(req,res);\n" +
//                "});\n" +
//                "\n" +
//                "var RouteManager ={\n" +
//                "\t\"findRoute\":function(req,res){\n" +
//                "\t\tvar handler = this.routes[req.url];\n" +
//                "\t\tif (!handler) throw \"cannot find route \" + req.url;\n" +
//                "\t\thandler.call(this,req,res);\n" +
//                "\t},\n" +
//                "\t\"routes\":{\n" +
//                "\t\t\t\"/json\":function(req,res){\n" +
//                "\t\t\t\t//this.sleep(5000);\n" +
//                "\t\t\t\tvar message = fs.readFileSync('./message.json','utf8');\n" +
//                "\t\t\t\tres.writeHead(200, {'Content-Type': 'application/json'});\n" +
//                "\t\t\t\tres.write(message.toString());\n" +
//                "\t\t\t\tres.end();\n" +
//                "\t\t\t},\n" +
//                "\t\t\t\"/xml\":function(req,res){\n" +
//                "\t\t\t\tvar message = fs.readFileSync('./message.xml','utf8');\n" +
//                "\t\t\t\tres.writeHead(200, {'Content-Type': 'application/xml'});\n" +
//                "\t\t\t\tres.write(message.toString());\n" +
//                "\t\t\t\tres.end();\n" +
//                "\t\t\t},\n" +
//                "\t\t\t\"/120/json?arg1=hello&arg2=world\":function(req,res){\n" +
//                "\t\t\t\t\tif (!req.headers[\"test-header\"]) throw \"no test-header found!!\";\n" +
//                "\t\t\t\t\tres.setHeader(\"test-response-header\",req.headers[\"test-header\"]);\n" +
//                "\t\t\t\t\tthis.routes[\"/json\"](req,res);\n" +
//                "\t\t\t},\n" +
//                "\t\t\t\"/json?post\":function(req,res){\n" +
//                "\t\t\t\treq.on('data',function(data){\n" +
//                "\t\t\t\t\tconsole.log(\"[SERVER] data = \", data);\n" +
//                "\t\t\t\t\tres.writeHead(200, {'Content-Type': 'application/json'});\n" +
//                "\t\t\t\t\t//res.writeHead(200, {'Content-Type': 'text/plain'});\n" +
//                "\t\t\t\t\tres.write(data.toString());\n" +
//                "\t\t\t\t\tres.end();\n" +
//                "\t\t\t\t});\n" +
//                "\t\t\t\t\t\n" +
//                "\t\t\t},\n" +
//                "\t\t\t\"/json/empty\":function(req,res){\n" +
//                "\t\t\t\tres.writeHead(204, {'Content-Type': 'application/json'});\n" +
//                "\t\t\t\tres.end();\n" +
//                "\t\t\t},\n" +
//                "\t\t\t\"/xml/empty\":function(req,res){\n" +
//                "\t\t\t\tres.writeHead(204, {'Content-Type': 'application/xml'});\n" +
//                "\t\t\t\tres.end();\n" +
//                "\t\t\t}\n" +
//                "\t},\n" +
//                "\t\"sleep\":function(ms){\n" +
//                "\t\t\n" +
//                "    var stop = new Date().getTime();\n" +
//                "    \twhile(new Date().getTime() < stop + ms) {\n" +
//                "      ;\n" +
//                "    \t}\n" +
//                "\t}\n" +
//                "\n" +
//                "};\n" +
//                "\n" +
//                "\n" +
//                "\n" +
//                "\n" +
//                "\n" +
//                "\n" +
//                "httpSrv.on('error',function(err){\n" +
//                "\tconsole.error('error starting http test server',err);\n" +
//                "});\n" +
//                "\n" +
//                "httpSrv.listen(4444);\n" +
//                "\n" +
//                "console.log('http server Listening on port ' + 4444);");

////        CharStream input = CharStreams.fromString("function foo()\n" +
////                "{\n" +
////                "    var o = Error();\n" +
////                "    for(let i in o)\n" +
////                "    {\n" +
////                "        o[i];\n" +
////                "    }\n" +
////                "}\n" +
////                "\n" +
////                "var bb = foo();");
////        CharStream input = CharStreams.fromString("var q;\n" +
////                "function g(){\n" +
////                "\tq = g.caller;\n" +
////                "\treturn 7;\n" +
////                "}\n" +
////                "\n" +
////                "\n" +
////                "var a = [1, 2, 3];\n" +
////                "a.length = 4;\n" +
////                "Object.defineProperty(Array.prototype, \"3\", {get : g});\n" +
////                "[4, 5, 6].concat(a);\n" +
////                "q(0x77777777, 0x77777777, 0);");
//        //CharStream input = CharStreams.fromString("x>=y");
//        //ANTLRInputStream input = new ANTLRInputStream(System.in);
//
//        // 构造词法分析器
////        ECMAScriptLexer lexer=new ECMAScriptLexer(input);
////
////        CommonTokenStream tokens = new CommonTokenStream(lexer);
////
//        // 实例化解析器
//        ECMAScriptParser parser = new ECMAScriptParser(tokens);
        // 构造词法分析器
        JavaScriptLexer lexer = new JavaScriptLexer(input);

        CommonTokenStream tokens = new CommonTokenStream(lexer);
        // 实例化解析器
        JavaScriptParser parser = new JavaScriptParser(tokens);
//
        ParseTree tree = parser.program();

        // 构造词法分析器
        JavaScriptLexer lexer2 = new JavaScriptLexer(input2);

        CommonTokenStream tokens2 = new CommonTokenStream(lexer2);
        // 实例化解析器
        JavaScriptParser parser2 = new JavaScriptParser(tokens2);
//
        ParseTree tree2 = parser2.program();


//        HelloBaseVisitor visitor = new HelloBaseVisitor();
//
//        System.out.println(visitor.visit(tree));

//        System.out.println(tree.getText());
//
//        System.out.println(tree.toStringTree(parser));

        //将提取出来的树转化成了自己定义的树
        TreeNode root =  TreeGet.getTree(tree,parser);
        TreeNode root2 = TreeGet.getTree(tree2,parser2);
//        System.out.println(root.gettext());
//        //System.out.println(root.getpath(root));
//        System.out.println(root2.gettext());



//        TreeNode child1 = root.getChlidren().get(0);
//        //System.out.println(root.getStatement());
//        TreeNode child2 = child1.getChlidren().get(0);
//        TreeNode child3 = child2.getChlidren().get(0);
//        TreeNode child4 = child3.getChlidren().get(0);
//
//
//
//        System.out.println(child1.getngram(3));
//        System.out.println(child2.getngram(3));
//        System.out.println(child3.getngram(3));
//        System.out.println(child4.getngram(3));
//
//        System.out.println(child1.getnodeProbability(Model,3));
//        System.out.println(child2.getnodeProbability(Model,3));
//        System.out.println(child3.getnodeProbability(Model,3));
//        System.out.println(child4.getnodeProbability(Model,3));
//
//        System.out.println(root.getAllnode().size());
//
//        System.out.println(NodeUtis.getMaxProbabilitynode(root,Model,3));
//
//
//        System.out.println(root.getstatemetnodelist("sourceElement").size());

//        JavaScriptLMGenertator genertator = new JavaScriptLMGenertator(Model,3);
//        genertator.init(new Seed(root),new Seed(root2));
//        System.out.println(genertator.generate());




//        for(int i =0 ;i<child1.getChlidren().size();i++){
//            System.out.println(child1.getChlidren().get(i).getStatement());
//        }


//        ParseTreeWalker walker = new ParseTreeWalker();
//
//        ECMAScriptBaseListener listener = new ECMAScriptBaseListener();
//
//        walker.walk(listener,tree);




    }
}

