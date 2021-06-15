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


public class JavaScriptLSTMGenerator2 implements LMGenerator {

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
        //System.out.println("id  is " + id);
        String aaa = id.length()+"-" + id +res;
        //System.out.println("res is" + res);
        return aaa;

//        TreeNode fuzzNode = fuzzSeed.lastUpdate == null ? fuzzSeed.Candidate.poll() : fuzzSeed.lastUpdate;
//
//        //System.out.println("fuzzNode is " + fuzzNode);
//        //System.out.println("fuzzNodeCount is " + fuzzNode.fuzzCount);
//        List<String> sequence = fuzzNode.getAncestorSequence(fuzzNode);
//        //进行预测
//        //System.out.println("sequence is " + sequence);
//        lstmPredict.load_model();
//        lstmPredict.load_data();
//        lstmPredict.gen_cand(sequence);
//        List<String> cand = lstmPredict.getCand_list();
//        //System.out.println("cand is -----" + cand);
//
//
//        String candCrop = cand.get(k);
//
//        List<TreeNode> cropSeedcandList = cropSeed.getRoot().getStatementNodeList(candCrop);
//        while (cropSeedcandList.size() == 0) {
//            candCrop = cand.get(++k);
//            cropSeedcandList = cropSeed.getRoot().getStatementNodeList(candCrop);
//        }
//
//        TreeNode cropNode = cropSeedcandList.get(random.nextInt(cropSeedcandList.size()));
//        //System.out.println("cropNode is ----" + cropNode.gettext());
//
//        TreeNode cropNodeCopy = TreeGet.TreeCopy(cropNode);
//        //进行变量合法化
//        Set<String> deleteVar = getVarIdentifier(fuzzNode);
//        //System.out.println("deleteVar is " + deleteVar);
//        Set<String> fuzzSeedVar = new HashSet<>();
//        for (String var : fuzzSeed.identifier) {
//            if (!deleteVar.contains(var)) {
//                fuzzSeedVar.add(var);
//            }
//        }
//        //System.out.println("fuzzSeedVar is " + fuzzSeedVar);
//        if(fuzzSeedVar.size()!=0)
//            replaceIdentifier(fuzzSeedVar, getCropUnIdentifier(cropNodeCopy, getVarIdentifier(cropNodeCopy)));
//        //替换
//        NodeUtils.replace(fuzzNode, cropNodeCopy);
//        //产生的新Seed
//        fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzSeed.root));
//        initNodeProbability(lstmPredict, fuzzNewSeed, fuzzNewSeed.root);
//        getIdentifier(fuzzNewSeed);
//        String res = fuzzNewSeed.getRoot().gettext();
//
//        NodeUtils.recover(cropNodeCopy, fuzzNode);
//        //System.out.println("fuzzSeed is ------" + fuzzSeed.root.gettext());
//        fuzzSeed.lastUpdate = fuzzNode;
//        fuzzNode.fuzzCount++;
//        fuzzSeed.fuzzCount++;
//        return res;


        //return "aaaaaaa";
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
            getIdentifier(curSeed);
            //System.out.println("identifier is " + curSeed.identifier);

            //System.out.println("canditate   is  " + curSeed.Candidate);
            //System.out.println("----------------------------------------------------------------------");

        }

        for (Seed curSeed : cropSeedList) {
            getIndexMap(curSeed);
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
            fuzzSeedList.remove(fuzzSeed);
            fuzzSeedList.add(fuzzNewSeed);

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

        //System.out.println("cand is -----" + cand);
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
        //进行变量合法化
        Set<String> deleteVar = getVarIdentifier(fuzzNode);
        //System.out.println("deleteVar is " + deleteVar);
        Set<String> fuzzSeedVar = new HashSet<>();
        for (String var : fuzzSeed.identifier) {
            if (!deleteVar.contains(var)) {
                fuzzSeedVar.add(var);
            }
        }
        //System.out.println("fuzzSeed.identifier is " + fuzzSeed.identifier);
        //System.out.println("fuzzSeedVar is " + fuzzSeedVar);
        if (fuzzSeedVar.size() != 0)
            replaceIdentifier(fuzzSeedVar, getCropUnIdentifier(cropNodeCopy, getVarIdentifier(cropNodeCopy)));
        //替换
        // System.out.println("变量替换完成");
        NodeUtils.replace(fuzzNode, cropNodeCopy);
        //产生的新Seed
        fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzSeed.root));
        initNodeProbability(lstmPredict, fuzzNewSeed, fuzzNewSeed.root);
        getIdentifier(fuzzNewSeed);

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
        Set<String> deleteVar = getVarIdentifier(fuzzNode);
        //System.out.println("deleteVar is " + deleteVar);
        Set<String> fuzzSeedVar = new HashSet<>();
        for (String var : fuzzSeed.identifier) {
            if (!deleteVar.contains(var)) {
                fuzzSeedVar.add(var);
            }
        }
        //System.out.println("fuzzSeedVar is " + fuzzSeedVar);
        if (fuzzSeedVar.size() != 0)
            replaceIdentifier(fuzzSeedVar, getCropUnIdentifier(cropNodeCopy, getVarIdentifier(cropNodeCopy)));
        //替换
        NodeUtils.replace(fuzzNode, cropNodeCopy);
        //产生的新Seed
        fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzSeed.root));
        initNodeProbability(lstmPredict, fuzzNewSeed, fuzzNewSeed.root);
        getIdentifier(fuzzNewSeed);

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

    public void getIdentifier(Seed seed) {
        TreeNode root = seed.root;
        List<TreeNode> list = new ArrayList<>();
        list = root.getStatementNodeList("variableDeclaration");

        HashSet<String> result = new HashSet<>();
        for (TreeNode treeNode : list) {

            while (treeNode != null && treeNode.getChildrenCount() != 0) {
                if (treeNode.statement.equals("identifier")) {
                    result.add(treeNode.children.get(0).children.get(0).getStatement());
                    break;
                } else {
                    treeNode = treeNode.children.get(0);
                }

            }
        }

        seed.identifier = result;
    }

    public Set<String> getVarIdentifier(TreeNode root) {
        List<TreeNode> list = new ArrayList<>();
        list = root.getStatementNodeList("variableDeclaration");

        HashSet<String> result = new HashSet<>();
        for (TreeNode treeNode : list) {

            while (treeNode != null && treeNode.getChildrenCount() != 0) {
                if (treeNode.statement.equals("identifier")) {
                    result.add(treeNode.children.get(0).children.get(0).getStatement());
                    break;
                } else {
                    treeNode = treeNode.children.get(0);
                }

            }
        }
        return result;

    }

    public Map<String, List<TreeNode>> getCropUnIdentifier(TreeNode root, Set<String> set) {
        List<TreeNode> list = new ArrayList<>();
        list = root.getStatementNodeList("identifier");

        HashMap<String, List<TreeNode>> cropUnIdentifierMap = new HashMap<>();
        for (TreeNode treeNode : list) {
            String treeNodeText = treeNode.children.get(0).children.get(0).getStatement();
            TreeNode treeNode1 = treeNode.children.get(0).children.get(0);
            if (!set.contains(treeNodeText)) {
                if (!cropUnIdentifierMap.containsKey(treeNodeText)) {
                    ArrayList<TreeNode> treeNodeList = new ArrayList<>();
                    treeNodeList.add(treeNode1);
                    cropUnIdentifierMap.put(treeNodeText, treeNodeList);
                } else {
                    List<TreeNode> list2 = cropUnIdentifierMap.get(treeNodeText);
                    list2.add(treeNode1);
                    cropUnIdentifierMap.put(treeNodeText, list2);

                }
            }

        }
        return cropUnIdentifierMap;


    }

    public void replaceIdentifier(Set<String> SeedIdentifier, Map<String, List<TreeNode>> map) {
        List<String> ls = Arrays.asList(SeedIdentifier.toArray(new String[0]));

        for (List<TreeNode> list : map.values()) {
            String temp = ls.get(random.nextInt(ls.size()));
            for (TreeNode treeNode : list) {
                treeNode.setStatement(temp);
            }
        }
    }

    public void getIndexMap(Seed seed) {
        TreeNode root = seed.root;
        Set<String> set = root.getAllStatement();
        for (String statement : set) {
            seed.StatementIndexTreeNode.put(statement, root.getStatementNodeList(statement));
        }

    }

}
