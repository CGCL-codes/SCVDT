package edu.berkeley.cs.jqf.examples.js;

import com.alibaba.fastjson.JSONObject;
import edu.berkeley.cs.jqf.fuzz.LM.LMGenerator;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.LSTM.LSTMPredict;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.NodeUtils;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeGet;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeNode;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.Seed;

import org.python.antlr.ast.Str;

import java.util.*;


public class JavaScriptLSTMGenerator3 implements LMGenerator {

    private Seed fuzzSeed;
    private Seed cropSeed;
    private LSTMPredict lstmPredict;
    private Seed fuzzNewSeed;

    private int K;//k的范围为0-9 取不同概率的节点
    private int N;//每个节点最多替换的次数
    private int M;//选取的Candidate队列的长度
    private int id;

    private ArrayList<String> Sequence = new ArrayList<String>();

    private Random random = new Random();

    private List<Seed> fuzzSeedList;
    private List<Seed> cropSeedList;

    @Override
    public String generate() {
        fuzzSeed = fuzzSeedList.get(0);//队列头的元素
        fuzzSeedList.remove(0);
        fuzzSeedList.add(fuzzSeed);
        String res = fuzzSeed.getRoot().gettext();
        String id = fuzzSeed.id + "-" + fuzzSeed.parentId;
        System.out.println("id  is " + id);
        String aaa = id.length()+"-" + id +res;
        //System.out.println("res is" + res);
        return aaa;
    }

    @Override
    public void init(List<Seed> fuzzSeedList, List<Seed> cropSeedList, JSONObject configObject) {
//        this.fuzzSeed = fuzzSeed;
//        this.cropSeed = cropSeed;
        this.K = configObject.getIntValue("K");
        this.N = configObject.getIntValue("N");
        this.M = configObject.getIntValue("M");
        //System.out.println("" + K + N + M);
        this.lstmPredict = new LSTMPredict();
        //todo
        lstmPredict.load_model();
        lstmPredict.load_data();
        id = 1;
        for (Seed curSeed : fuzzSeedList) {
            curSeed.id = id++;
            curSeed.parentId = 0;
            curSeed.root.probability = 0;//set the probability of root as 0, which is not considered to be mutated
            initNodeProbability(lstmPredict, curSeed, curSeed.root);
            Sequence.clear();
            //System.out.println("identifier is " + curSeed.identifier);

            //System.out.println("canditate   is  " + curSeed.Candidate);
            //System.out.println("----------------------------------------------------------------------");

        }


        fuzzSeed = fuzzSeedList.get(0);
        cropSeed = cropSeedList.get(0);
        this.fuzzSeedList = fuzzSeedList;
        this.cropSeedList = cropSeedList;


    }

    @Override
    public void update(int r) {
        if (r == 1) {
            System.out.println("11111111111111111update");
            case1mutate();
            fuzzNewSeed.id = id++;
            fuzzNewSeed.parentId = fuzzSeed.id;
            fuzzSeedList.add(fuzzNewSeed);
            fuzzSeed.lastUpdate.fuzzCount++;


        } else if (r == 2) {
            System.out.println("222222222222222222update");
            case2mutate();
            fuzzNewSeed.id = id++;
            fuzzNewSeed.parentId = fuzzSeed.id;
            fuzzSeedList.add(fuzzNewSeed);
            fuzzSeed.lastUpdate.fuzzCount++;
            if (fuzzSeed.lastUpdate.fuzzCount >= N) {
                if (fuzzSeed.Candidate.size() == 0) {
                    //换种子
                    fuzzSeedList.remove(fuzzSeed);
                    cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));

                }
                fuzzSeed.lastUpdate = null;
            }


        } else if (r == 3) {
            System.out.println("3333333333333333update");
            case2mutate();
            fuzzNewSeed.id = id++;
            fuzzNewSeed.parentId = fuzzSeed.id;
            fuzzSeedList.add(fuzzNewSeed);
            fuzzSeed.lastUpdate.fuzzCount++;
            if (fuzzSeed.lastUpdate.fuzzCount >= N) {
                if (fuzzSeed.Candidate.size() == 0) {
                    //换种子
                    fuzzSeedList.remove(fuzzSeed);
                    cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));

                }
                fuzzSeed.lastUpdate = null;
            }

        } else if (r == 4) {
            System.out.println("4444444444444444444update");
            fuzzSeedList.remove(fuzzSeed);
            cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));

        } else {
            fuzzSeedList.add(fuzzNewSeed);
            fuzzSeed.lastUpdate.fuzzCount = 0;
        }

    }

    public void case1mutate() {
        TreeNode fuzzNode = fuzzSeed.lastUpdate == null ? fuzzSeed.Candidate.poll() : fuzzSeed.lastUpdate;

        //System.out.println("fuzzNode is " + fuzzNode);
        //System.out.println("fuzzNodeCount is " + fuzzNode.fuzzCount);
        List<String> sequence = fuzzNode.getAncestorSequence(fuzzNode);
        //进行预测
        //System.out.println("sequence is " + sequence);
//        lstmPredict.load_model();
//        lstmPredict.load_data();
        lstmPredict.gen_cand(sequence);
        List<String> cand = lstmPredict.getCand_list();

        System.out.println("cand is -----" + cand);
        double[] probabilitycand = lstmPredict.getProbability();
        Map<Double, Integer> mapIndex = new HashMap<>();

        List<Double> absProbability = new ArrayList<>();
        for (int i = 0; i <= 9; i++) {
            absProbability.add(probabilitycand[i]);
            mapIndex.put(probabilitycand[i], i);
        }
        absProbability.sort((o1, o2) -> Double.compare(Math.abs(o2 - fuzzNode.probability), Math.abs(o1 - fuzzNode.probability)));


        List<String> result = new ArrayList<>();//概率与之最不一样的节点候选列表 10

        for (double a : absProbability) {
            result.add(cand.get(mapIndex.get(a)));
        }

        int k = 0;
        String candCrop;

        List<TreeNode> cropSeedcandList = null;
        while (cropSeedcandList == null) {
            if (k == K) {
                cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));
                k = 0;
            }
            candCrop = result.get(k++);
            //System.out.println("candCrop is -----" + candCrop);
            cropSeedcandList = cropSeed.StatementIndexTreeNode.getOrDefault(candCrop, null);
        }

        TreeNode cropNode = cropSeedcandList.get(random.nextInt(cropSeedcandList.size()));
        //System.out.println("cropNode is ----" + cropNode.gettext());

        TreeNode cropNodeCopy = TreeGet.TreeCopy(cropNode);

        NodeUtils.replace(fuzzNode, cropNodeCopy);
        //产生的新Seed
        fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzSeed.root));

        HashSet<String> global = new HashSet<>();
        HashSet<String> func = new HashSet<>();
        var_hoisting(fuzzNewSeed.root,global,func);
        resolve_id(fuzzNewSeed.root,global,func);


        initNodeProbability(lstmPredict, fuzzNewSeed, fuzzNewSeed.root);
        NodeUtils.recover(cropNodeCopy, fuzzNode);
        fuzzSeed.lastUpdate = fuzzNode;
    }

    public void case2mutate() {
        TreeNode fuzzNode = fuzzSeed.lastUpdate == null ? fuzzSeed.Candidate.poll() : fuzzSeed.lastUpdate;

        //System.out.println("fuzzNode is " + fuzzNode);
        //System.out.println("fuzzNodeCount is " + fuzzNode.fuzzCount);
        List<String> sequence = fuzzNode.getAncestorSequence(fuzzNode);
        //进行预测
        //System.out.println("sequence is " + sequence);
//        lstmPredict.load_model();
//        lstmPredict.load_data();
        lstmPredict.gen_cand(sequence);
        List<String> cand = lstmPredict.getCand_list();

        //System.out.println("cand is -----" + cand);

        int k = 0;
        String candCrop = cand.get(k);
        //System.out.println("candCrop is -----" + candCrop);
        List<TreeNode> cropSeedcandList = cropSeed.StatementIndexTreeNode.getOrDefault(candCrop, null);
        while (cropSeedcandList == null) {
            candCrop = cand.get(++k);
            cropSeedcandList = cropSeed.StatementIndexTreeNode.getOrDefault(candCrop, null);
        }

        TreeNode cropNode = cropSeedcandList.get(random.nextInt(cropSeedcandList.size()));
        //System.out.println("cropNode is ----" + cropNode.gettext());

        TreeNode cropNodeCopy = TreeGet.TreeCopy(cropNode);
        //进行变量合法化

        NodeUtils.replace(fuzzNode, cropNodeCopy);
        //产生的新Seed
        fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzSeed.root));

        HashSet<String> global = new HashSet<>();
        HashSet<String> func = new HashSet<>();
        var_hoisting(fuzzNewSeed.root,global,func);
        resolve_id(fuzzNewSeed.root,global,func);

        initNodeProbability(lstmPredict, fuzzNewSeed, fuzzNewSeed.root);
        NodeUtils.recover(cropNodeCopy, fuzzNode);
        fuzzSeed.lastUpdate = fuzzNode;

    }


    public void initNodeProbability(LSTMPredict lstmPredict, Seed seed, TreeNode treeNode) {
        //todo
        if (treeNode.parent != null)
            Sequence.add(treeNode.parent.statement);
        for (int i = 0; i < treeNode.getChildrenCount(); i++) {
            initNodeProbability(lstmPredict, seed, (treeNode.children).get(i));
        }
        if (treeNode.statement.equals("terminalNodeImpl") || treeNode.getChildrenCount() == 0) {
            treeNode.probability = 0;
            Sequence.remove(Sequence.size() - 1);
            return;
        }
        if (Sequence.size() > 2) {
            //System.out.println("184184184"+Sequence);
            lstmPredict.gen_cand(Sequence);
            List<String> cand = lstmPredict.getCand_list();
            //System.out.println("187187187"+treeNode.statement);
            treeNode.probability = (cand.indexOf(treeNode.statement) == -1) ? 0 : (lstmPredict.getProbability())[cand.indexOf(treeNode.statement)];

            if (seed.Candidate.size() < M)
                seed.Candidate.add(treeNode);
            else if (treeNode.probability > seed.Candidate.peek().probability) {
                seed.Candidate.poll();
                seed.Candidate.add(treeNode);
            }
            Sequence.remove(Sequence.size() - 1);
        } else if (Sequence.size() > 0) {
            treeNode.probability = 0;
            Sequence.remove(Sequence.size() - 1);
            return;
        }

    }

    public void var_hoisting(TreeNode root, HashSet<String> global_var,HashSet<String> func_list){
        String NodeType = root.getStatement();
        /*
        When meets a functionDeclaration, we assume that the following variableDeclarations are local, so skip it.
        * */
        if(NodeType.equals("functionDeclaration")) {
            func_list.add(root.children.get(1).children.get(0).children.get(0).statement);
            return;
        }
        /*
        This branch is remained to be improved:
            case 1: (e.g) var f = function(){...}
            case 2: (e.g) var double = num => num * 2
        * */
        else if(NodeType.equals("functionExpression"))
            return;
        /*
        When there is a variableDeclarationList, that's what we want. We collect all the assignable node
        which implies an new identifier
        * */
        else if(NodeType.equals("variableDeclarationList")&&root.children.get(0).children.get(0).children.get(0).getStatement().equals("var")){
            List<TreeNode> childs = root.getStatementNodeList("assignable");
            for(TreeNode child:childs)
                global_var.add(child.children.get(0).children.get(0).children.get(0).getStatement());
        }
        /*
        Other ways, we do dfs
        * */
        else
            for(TreeNode childNode:root.children){
                var_hoisting(childNode,global_var,func_list);
            }
    }

    public void resolve_id(TreeNode root, HashSet var_list, HashSet func_list){
        String NodeType = root.getStatement();
        if(NodeType.equals("functionDeclaration")||NodeType.equals("functionExpression")) {
            HashSet<String> local_var = new HashSet<>();
            for(TreeNode childNode:root.children){
                var_hoisting(childNode,local_var,func_list);
            }
            local_var.addAll(var_list);
            for(TreeNode childNode:root.children){
                if(childNode.getStatement().equals("functionBody"))
                    resolve_id(childNode,local_var,func_list);
            }
        }
        else if(NodeType.equals("argumentsExpression")){
            resolve_argumentsExpression(root,var_list,func_list);
        }
        else if(NodeType.equals("identifier")){
            List<String> result = new ArrayList<>(var_list);
            //root.parent.parent.statement.equals("argumentsExpression")
            if(!var_list.contains(root.children.get(0).children.get(0).getStatement())&&result.size()!=0&&!root.parent.parent.statement.equals("argumentsExpression"))
                root.children.get(0).children.get(0).statement = result.get(random.nextInt(result.size()));
        }
        else
            for(TreeNode childNode:root.children){
                resolve_id(childNode,var_list,func_list);
            }
    }

    public void resolve_argumentsExpression(TreeNode root, HashSet var_list, HashSet func_list){
        /**
         * This function is called when there is a functionCall
         * We assume that a functionCall is combined with first part callee and second part arguments,
         * When pre-traversing the callee node, the last "identifier" node must be the direct function name,
         * so we select the alternative id for the last identifier from func_list.
         * Finally, for the arguments, we simply check every argument and try to resolve id.
         *
         */
        //如果callee为identifier
        List<String> result = new ArrayList<>(var_list);
        TreeNode callee = root.children.get(0);
        List<TreeNode> id_in_callee = callee.getStatementNodeList("identifier");
        for(int i=0;i<id_in_callee.size()-1;i++){
            if(result.size()!=0){
                id_in_callee.get(i).children.get(0).children.get(0).statement = result.get(random.nextInt(result.size()));
            }
        }
        result = new ArrayList<>(func_list);
        if(result.size()!=0){
            id_in_callee.get(id_in_callee.size()-1).children.get(0).children.get(0).statement = result.get(random.nextInt(result.size()));
        }
        //resolve arguments
        resolve_id(root.children.get(1), var_list, func_list);
    }


}
