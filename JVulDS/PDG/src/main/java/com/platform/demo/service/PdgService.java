package com.platform.demo.service;

import com.generatepdg.pdg.node.*;
import com.generatepdg.pe.*;
import com.platform.demo.Config;
import com.platform.demo.MainTest;
import com.platform.demo.graphNode.FileNode;
import com.platform.demo.graphNode.MethodNode;
import com.platform.demo.graphNode.StatementNode;
import com.platform.demo.relationship.*;
import com.platform.demo.repository.*;
import com.platform.demo.utils.ZipFiles;
import com.platform.demo.utils.ZipUtils;
import net.lingala.zip4j.exception.ZipException;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.eclipse.jdt.core.dom.CompilationUnit;
import org.springframework.stereotype.Service;
import com.generatepdg.ast.TinyPDGASTVisitor;
import com.generatepdg.cfg.node.CFGNodeFactory;
import com.generatepdg.pdg.PDG;
import com.generatepdg.pdg.edge.PDGControlDependenceEdge;
import com.generatepdg.pdg.edge.PDGDataDependenceEdge;
import com.generatepdg.pdg.edge.PDGEdge;
import com.generatepdg.pdg.edge.PDGExecutionDependenceEdge;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.*;

@Service
public class PdgService {
    @Resource
    private FileRepository fileRepository;
    @Resource
    private MethodRepository methodRepository;
    @Resource
    private StatementRepository statementRepository;
    @Resource
    private RelationshipRepositoryCToM relationshipRepositoryCToM;
    @Resource
    private RelationshipRepositoryMToS relationshipRepositoryMToS;

    @Resource
    private RelationshipRepositoryDD relationshipRepositoryDD;
    @Resource
    private RelationshipRepositoryCD relationshipRepositoryCD;
    @Resource
    private RelationshipRepositoryED relationshipRepositoryED;

    public static long id;

    final private Map<Integer, Set<String>> xlsxMap= new HashMap<>();
    private int type = -1; //无
    final Set<String> api = new HashSet<>();
    final static List<String> operators = new ArrayList<>(Arrays.asList("+", "-", "*", "/", "/=", "+=", "-=", "*=", "%"));

    //Todo 先把文件当成输入 之后确定上传的文件存在哪里 文件类型
    public void addPDGNode(String path) {

        api.add("response.getWriter().println");
        api.add("System.load");
        api.add("System.loadLibrary");
        api.add("System.out.format");
        api.add("new File");
        api.add("new SecretKeySpec");
        api.add("Cipher.getInstance");
        api.add("MessageDigest.getInstance");
        api.add("Math.random");
        api.add("Class.forName");
        api.add("System.getenv");
        api.add("Runtime.getRuntime().exec");
        api.add("session.getID");

        getXlsxApi();


        final File target = new File(path);
        final List<File> files = Common.getFiles(target);

        for (File file : files) {

            FileNode fileNode = FileNode.builder().filePath(file.getAbsolutePath()).code(file.getName()).build();

            final List<MethodInfo> methods = new ArrayList<MethodInfo>();
            final CompilationUnit unit = TinyPDGASTVisitor.createAST(file);
            final List<MethodInfo> m = new ArrayList<MethodInfo>();
            final TinyPDGASTVisitor visitor = new TinyPDGASTVisitor(
                    file.getAbsolutePath(), unit, methods);
            unit.accept(visitor);
            methods.addAll(m);

            for (MethodInfo method : methods) {
                final PDG pdg = new PDG(method, new PDGNodeFactory(),
                        new CFGNodeFactory(), true, true, true);
                pdg.build();
                //不知道可不可以  试试。。。。
                MethodNode methodNode = MethodNode.builder().code(method.name).startLine(method.startLine).endLine(method.endLine)
                        .dirName(file.getParentFile().getName()).filePath(file.getPath()).classID(fileNode.getId()).build();

                //文件
                fileRepository.saveAll(new ArrayList<>(Arrays.asList(fileNode)));
                //方法
                methodRepository.saveAll(new ArrayList<>(Arrays.asList(methodNode)));


                Map<PDGNode<?>, StatementNode> pdgToGraph = new HashMap<>();
                boolean isCFGNode = false;
                List<StatementNode> statementNodes = new ArrayList<>();

                Map<String, String> variableInfo = new HashMap<>(); // 参数
                for (VariableInfo var : method.getParameters()){
                    variableInfo.put(var.name, var.type.name);
                }

                for (final PDGNode<?> pdgNode : pdg.getAllNodes()) {
                    buildVariableType(variableInfo, pdgNode);
                    if (pdgNode instanceof PDGControlNode) {
                        isCFGNode = true;
                    } else isCFGNode = false;

                    type = -1;
                    //MI 1
                    //AE 0

                    if (pdgNode.core instanceof ExpressionInfo){
                        extractAPI((ExpressionInfo)pdgNode.core); //MI
                        if (type == -1){
                            type = bugTypeUpdate(((ExpressionInfo)pdgNode.core).getExpressions(),variableInfo);  //MI
                        }
                        if (type == -1){
                            type = bugTypeUpdateAE(((ExpressionInfo)pdgNode.core).getExpressions(), variableInfo); //AE
                        }
                        if (type == -1){
                            type = bugTypeUpdateSE(((ExpressionInfo) pdgNode.core).getText());
                        }
                    }
                    else if (pdgNode.core instanceof StatementInfo){
                        extractAPI((StatementInfo) pdgNode.core);
                        if (type == -1){
                            type = bugTypeUpdate(((StatementInfo)pdgNode.core).getExpressions(),variableInfo);
                        }
                        if (type == -1){
                            type = bugTypeUpdateAE(((StatementInfo)pdgNode.core).getExpressions(), variableInfo); //AE
                        }
                        if (type == -1){
                            type = bugTypeUpdateSE(((StatementInfo) pdgNode.core).getText());
                        }
                    }


                    StatementNode statementNode = StatementNode.builder()
                            .code(pdgNode.core.getText())
                            .startLine(pdgNode.core.startLine)
                            .endLine(pdgNode.core.endLine)
                            .isCFGNode(isCFGNode)
                            .methodID(methodNode.getId())
                            .type(type)
                            .build();
                    statementNodes.add(statementNode);
                    pdgToGraph.put(pdgNode, statementNode);

                    if (pdgNode instanceof PDGMethodEnterNode) {
                        Enter enter = Enter.builder().parent(methodNode).child(statementNode).build();
                        relationshipRepositoryMToS.saveAll(new ArrayList<>(Arrays.asList(enter)));
                    }
                }

                //类与方法之间的关系
                IsClassof relationship1 = IsClassof.builder().parent(fileNode).child(methodNode).build();
                relationshipRepositoryCToM.saveAll(new ArrayList<>(Arrays.asList(relationship1)));


                //结点
                statementRepository.saveAll(statementNodes);

                for (final PDGEdge edge : pdg.getAllEdges()) {
                    if (edge instanceof PDGControlDependenceEdge) {
                        CD cd = CD.builder().parent(pdgToGraph.get(edge.fromNode)).child(pdgToGraph.get(edge.toNode)).message(edge.getDependenceString()).build();
                        relationshipRepositoryCD.saveAll(new ArrayList<>(Arrays.asList(cd)));
                    } else if (edge instanceof PDGDataDependenceEdge) {
                        DD dd = DD.builder().parent(pdgToGraph.get(edge.fromNode)).child(pdgToGraph.get(edge.toNode)).message(edge.getDependenceString()).build();
                        relationshipRepositoryDD.saveAll(new ArrayList<>(Arrays.asList(dd)));

                    } else if (edge instanceof PDGExecutionDependenceEdge) {
                        FlowsTo ed = FlowsTo.builder().parent(pdgToGraph.get(edge.fromNode)).child(pdgToGraph.get(edge.toNode)).message(edge.getDependenceString()).build();
                        relationshipRepositoryED.saveAll(new ArrayList<>(Arrays.asList(ed)));
                    }
                }
            }
        }
    }

    private void buildVariableType(Map<String,String> variableInfo, PDGNode<?> pdgNode) {
        //for (PDGNode<?> pdgNode : pdgNodes){
        ProgramElementInfo node = pdgNode.core;
        if (node instanceof StatementInfo){
            StatementInfo statementInfo =  (StatementInfo)node;
            if (statementInfo.getCategory().id.equals("VARIABLEDECLARATION")){
                List<ProgramElementInfo> expressions = statementInfo.getExpressions();
                String type = null;
                for (ProgramElementInfo expression : expressions){
                    if (expression instanceof TypeInfo){
                        type = expression.getText();
                    }
                    else if (expression instanceof ExpressionInfo) {
                        List<ProgramElementInfo> expressions1 = ((ExpressionInfo) expression).getExpressions();
                        for (ProgramElementInfo expression1 : expressions1) {
                            if (expression1 instanceof ExpressionInfo && ((ExpressionInfo) expression1).getCategory().id.equals("SIMPLENAME")){
                                variableInfo.put(expression1.getText(),type);
                                break;
                            }
                        }
                    }
                }
            }
        }
        //}
    }
    private void getXlsxApi() {
        String path = System.getProperty("user.dir");
        //System.out.println(path);
        try {
            InputStream inputStream = new FileInputStream(new File(path + File.separator + "rules.xlsx"));
            Workbook book = new XSSFWorkbook(inputStream);
            for (int i = 0;i < 4;i++){
                Sheet sheet = book.getSheetAt(i);
                Set<String> set = new HashSet<>();
                if (sheet != null){
                    int first = sheet.getFirstRowNum();
                    int last = sheet.getLastRowNum();
                    for (int j = first + 1;j <= last; j++){
                        Row row = sheet.getRow(j);
                        String str = row.getCell(0).toString();
                        if (str != null && str.length() != 0) {
                            set.add(str);
                        }
                    }
                }
                xlsxMap.put(i, set);
            }
            inputStream.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private int bugTypeUpdate(List<ProgramElementInfo> expressionInfos, Map<String, String> variableInfo){
        for (ProgramElementInfo expressionInfo : expressionInfos) {
            if (expressionInfo instanceof ExpressionInfo && ((ExpressionInfo) expressionInfo).category.id.equals("METHODINVOCATION")) {
                ProgramElementInfo qualifier = ((ExpressionInfo) expressionInfo).getQualifier();
                if (qualifier != null) {
                    String text = qualifier.getText();
                    if (variableInfo.get(text) != null) {
                        String type = variableInfo.get(text);
                        List<ProgramElementInfo> invokes = ((ExpressionInfo) expressionInfo).getExpressions();
                        for (ProgramElementInfo invoke : invokes) {
                            //System.out.println(invoke.getText());
                            if ((type.equals("Connection") && invoke.getText().equals("setCatalog"))
                                    || (type.equals("HttpServletResponse") && invoke.getText().equals("sendError"))
                                    || (type.equals("HttpServletResponse") && invoke.getText().equals("addCookie"))
                                    || (type.equals("KeyGenerator ") && invoke.getText().equals("generateKey"))
                                    || (type.equals("SecureRandom") && invoke.getText().equals("setSeed"))
                                    || (type.equals("Logger") && invoke.getText().equals("log"))
                                    || (type.equals("Cookie") && invoke.getText().equals("setMaxAge"))
                                    || (type.equals("MessageDigest") && invoke.getText().equals("digest"))
                                    || (type.endsWith("DirContext") && invoke.getText().equals("search"))
                                    || (type.equals("MessageDigest") && invoke.getText().equals("update"))
                                    || (type.equals("HttpServletResponse") && invoke.getText().equals("addHeader"))
                                    || (type.equals("HttpServletResponse") && invoke.getText().equals("setHeader"))) {
                                return 1;
                            }
                            else if (type.equals("Statement") || type.equals("PreparedStatement")){
                                if(invoke.getText().indexOf("execute") != -1 || invoke.getText().equals("addBatch")){
                                    return 1;
                                }
                            }
                            else if (type.equals("Connection")){
                                if (invoke.getText().equals("prepareCall") || invoke.getText().equals("prepareStatement")
                                        || invoke.getText().equals("nativeSQL")){
                                    return 1;
                                }
                            }
                        }
                    }
                    if (bugTypeUpdate(((ExpressionInfo)expressionInfo).getExpressions(), variableInfo) == 1)
                        return 1;
                } else {
                    //log
                    SortedSet<String> references = expressionInfo.getReferencedVariables();
                    for (String reference : references) {
                        if (reference.equals("log")) return 1;
                    }
                }
            }
            else if (expressionInfo instanceof ExpressionInfo){
                if ((((ExpressionInfo)expressionInfo).getExpressions()).size() == 0) continue;
                if (bugTypeUpdate(((ExpressionInfo)expressionInfo).getExpressions(), variableInfo) == 1){
                    return 1;
                }
            }
            for (String s : api) {
                if (expressionInfo.getText().indexOf(s) != -1) {
                    return 1;
                }
            }
        }
        return -1;
    }

    private int bugTypeUpdateAE(List<ProgramElementInfo> expressionInfos, Map<String, String> variableInfo){
        // = ((StatementInfo) node.core).getExpressions();
        for (ProgramElementInfo expressionInfo : expressionInfos){
            if (expressionInfo instanceof OperatorInfo){
                String name = ((OperatorInfo) expressionInfo).name;
                if (name.equals("++") || name.equals("--")){
                    if (expressionInfos.size() == 2) {
                        for (ProgramElementInfo elementInfo : expressionInfos){
                            if (elementInfo.getText().equals("data")) return 0; //sard测试 TODO
                        }
                        //return 0;
                    }
                }
                else if (operators.contains(name) && expressionInfos.size() == 3){
                    for (ProgramElementInfo elementInfo : expressionInfos){
                        if (elementInfo.getText().equals("data")) return 0; //sard测试 TODO
                    }
                    //return -1;
                }
            }
            else if (expressionInfo instanceof ExpressionInfo){ //0
                if (((ExpressionInfo)expressionInfo).getExpressions() != null && ((ExpressionInfo)expressionInfo).getExpressions().size() != 0){
                    return bugTypeUpdateAE(((ExpressionInfo)expressionInfo).getExpressions(), variableInfo);
                }
                continue; //4.13 待会加回来
            }
            else {
                //直接匹配部分
                continue;
            }
        }
        return -1;
    }

    private int bugTypeUpdateSE(String str){
        if (str.indexOf("password")!=-1 || str.indexOf("Password")!=-1){
            return 2;
        }
        return -1;
    }

    public void extractAPI(StatementInfo statementInfo){
        for (ProgramElementInfo programElementInfo : statementInfo.getExpressions()){
            if (programElementInfo instanceof StatementInfo){
                extractAPI((StatementInfo)programElementInfo);
            }
            else if (programElementInfo instanceof ExpressionInfo){
                extractAPI((ExpressionInfo)programElementInfo);
            }
        }
    }

    private void extractAPI(ExpressionInfo expressionInfo) {
        if (expressionInfo.getApiName() != null){
            if (matchApi(expressionInfo.getApiName())){
                type = 1;
                return;
            }
            else type = -1;
        }

        for(ProgramElementInfo programElementInfo : expressionInfo.getExpressions()){
            if (programElementInfo instanceof ExpressionInfo){
                extractAPI((ExpressionInfo)programElementInfo);
            }
            else if (programElementInfo instanceof StatementInfo){
                extractAPI((StatementInfo)programElementInfo);
            }
        }
        ProgramElementInfo programElementInfo = expressionInfo.getQualifier();
        if (programElementInfo != null){
            if (programElementInfo instanceof ExpressionInfo){
                extractAPI((ExpressionInfo)programElementInfo);
            }
            else if (programElementInfo instanceof StatementInfo){
                extractAPI((StatementInfo)programElementInfo);
            }
        }

    }

    private boolean matchApi(String apiName) {
        for (Map.Entry<Integer, Set<String>> entry:xlsxMap.entrySet()){
            for (String s : entry.getValue()){
                if (entry.getKey() == 0){
                    if (apiName.indexOf(s + "()") != -1){
                        return true;
                    }
                }
                else if (entry.getKey() == 1){
                    int index = s.indexOf("*");
                    if (index == -1){
                        if (apiName.indexOf(s + "()") != -1){
                            return true;
                        }
                    }
                    else if (index == 0){
                        if (apiName.indexOf(s.substring(1)) != -1){
                            return true;
                        }
                    }
                    else {
                        if (apiName.indexOf(s.substring(0,index)) != -1){
                            return true;
                        }
                    }
                }
                else if (entry.getKey() == 2){
                    if (apiName.endsWith(s + "()")){
                        return true;
                    }
                }
                else if (entry.getKey() == 3){
                    if (apiName.equals(s + "()")){
                        return true;
                    }
                }
            }
        }
        return false;
    }

    //返回值 TODO:download存储在哪里的地址  与上传的文件
    public void downLoad(String path, HttpServletResponse response) {
        //TODO 需要改path

        final File f = new File(path);
        if (!f.exists()) {
            return;
        }

        String outPaths = Config.uploadBasePath + File.separator + "PDG";
        File out = new File(outPaths);

        if (out.exists()){
            MainTest.deleteFile(out.listFiles());
        }

        if (!out.exists()){
            out.mkdirs();
        }

        List<File> files = MainTest.getFiles(f);
        for (File file : files) {

            final List<MethodInfo> methods = new ArrayList<MethodInfo>();
            final CompilationUnit unit = TinyPDGASTVisitor.createAST(file);
            final List<MethodInfo> m = new ArrayList<MethodInfo>();
            final TinyPDGASTVisitor visitor = new TinyPDGASTVisitor(
                    file.getAbsolutePath(), unit, methods);
            unit.accept(visitor);
            methods.addAll(m);
            int createdGraphNumber = 0;

            //TODO 下载文件位置需要改
            String outPath = outPaths + File.separator + file.getName().replace(".java", "_pdg.dot");
            final BufferedWriter writer;
            try {
                writer = new BufferedWriter(new FileWriter(outPath));
                writer.write("digraph PDG {");
                writer.newLine();

                for (final MethodInfo method : methods) {

                    final PDG pdg = new PDG(method, new PDGNodeFactory(),
                            new CFGNodeFactory(), true, true, true);
                    pdg.build();
                    writePDG(pdg, createdGraphNumber++, writer);
                }

                writer.write("}");
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        response.setContentType("application/zip");
        response.setHeader("Content-Disposition", "attachment;filename=PDG.zip");
        try {
            ZipUtils.toZip(outPaths, response.getOutputStream(), true);
            ZipFiles.zipFile(outPaths, response.getOutputStream());
        } catch (IOException | ZipException e) {
            e.printStackTrace();
        }

        //之前单个文件下载功能部分
//            File file1 = new File(outPath);
//            // 获取文件名 - 设置字符集
//            String downloadFileName = new String(file1.getName().getBytes(StandardCharsets.UTF_8), "iso-8859-1");
//            // 以流的形式下载文件
//            InputStream fis;
//            fis = new BufferedInputStream(new FileInputStream(outPath));
//            byte[] buffer = new byte[fis.available()];
//            fis.read(buffer);
//            fis.close();
//            // 清空response
//            response.reset();
//            // 设置response的Header
//            response.addHeader("Content-Disposition", "attachment;filename=" + downloadFileName);
//            response.addHeader("Content-Length", "" + file1.length());
//            OutputStream toClient = new BufferedOutputStream(response.getOutputStream());
//            response.setContentType("application/octet-stream");
//            toClient.write(buffer);
//            toClient.flush();
//            toClient.close();
//
//            file1.delete();

        // }

    }

    private void writePDG(final PDG pdg,
                          final int createdGraphNumber,
                          final BufferedWriter writer) throws IOException {
        final MethodInfo method = pdg.unit;

        writer.write("subgraph cluster");
        writer.write(Integer.toString(createdGraphNumber));
        writer.write(" {");
        writer.newLine();

        writer.write("label = \"");
        writer.write(Common.getMethodSignature(method));
        writer.write("\";");
        writer.newLine();

        final Map<PDGNode<?>, Integer> nodeLabels = new HashMap<PDGNode<?>, Integer>();
        //final SortedSet<PDGNode<?>> nodes = pdg.getAllNodes();
        for (final PDGNode<?> node : pdg.getAllNodes()) {
            nodeLabels.put(node, nodeLabels.size());
        }

        for (final Map.Entry<PDGNode<?>, Integer> entry : nodeLabels.entrySet()) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(entry.getValue()));
            writer.write(" [style = filled, label = \"");
            writer.write(entry.getKey().getText().replace("\"", "\\\"")
                    .replace("\\\\\"", "\\\\\\\""));
            writer.write("\"");

            final PDGNode<?> node = entry.getKey();
            if (node instanceof PDGMethodEnterNode) {
                writer.write(", fillcolor = aquamarine");
            } else if (pdg.getExitNodes().contains(node)) {
                writer.write(", fillcolor = deeppink");
            } else if (node instanceof PDGParameterNode) {
                writer.write(", fillcolor = tomato");
            } else {
                writer.write(", fillcolor = white");
            }

            if (node instanceof PDGControlNode) {
                writer.write(", shape = diamond");
            } else if (node instanceof PDGParameterNode) {
                writer.write(", shape = box");
            } else {
                writer.write(", shape = ellipse");
            }

            writer.write("];");
            writer.newLine();
        }

        for (final PDGEdge edge : pdg.getAllEdges()) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.fromNode)));
            writer.write(" -> ");
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.toNode)));
            if (edge instanceof PDGDataDependenceEdge) {
                writer.write(" [style = solid, label=\""
                        + edge.getDependenceString() + "\"]");
            } else if (edge instanceof PDGControlDependenceEdge) {
                writer.write(" [style = dotted, label=\""
                        + edge.getDependenceString() + "\"]");
            } else if (edge instanceof PDGExecutionDependenceEdge) {
                writer.write(" [style = bold, label=\""
                        + edge.getDependenceString() + "\"]");
            }
            writer.write(";");
            writer.newLine();
        }

        writer.write("}");
        writer.newLine();
    }

}
