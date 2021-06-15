package edu.berkeley.cs.jqf.examples.js;

import com.alibaba.fastjson.JSONObject;
import edu.berkeley.cs.jqf.fuzz.LM.LMGenerator;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.LSTM.LSTMPredict;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.NodeUtils;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeGet;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeNode;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.Seed;


import java.util.*;


public class JavaScriptLSTMGenerator implements LMGenerator {

    private Seed fuzzSeed;
    private Seed cropSeed;
    private LSTMPredict lstmPredict;
    private Seed fuzzNewSeed;

    private int K ;//k的范围为0-9 取不同概率的节点

    private ArrayList<String> Sequence = new ArrayList<String>();

    private Random random = new Random();

    private List<Seed> fuzzSeedList;
    private List<Seed> cropSeedList;

    @Override
    public String generate() {
        TreeNode fuzzNode = fuzzSeed.lastUpdate == null ? fuzzSeed.Candidate.poll() : fuzzSeed.lastUpdate;

        //System.out.println("fuzzNode is " + fuzzNode);
        //System.out.println("fuzzNodeCount is " + fuzzNode.fuzzCount);
        List<String> sequence = fuzzNode.getAncestorSequence(fuzzNode);
        //进行预测
        //System.out.println("sequence is " + sequence);
        lstmPredict.load_model();
        lstmPredict.load_data();
        lstmPredict.gen_cand(sequence);
        List<String> cand = lstmPredict.getCand_list();
        //System.out.println("cand is -----" + cand);


        String candCrop = cand.get(K);

        List<TreeNode> cropSeedcandList = cropSeed.getRoot().getStatementNodeList(candCrop);
        while (cropSeedcandList.size() == 0) {
            candCrop = cand.get(++K);
            cropSeedcandList = cropSeed.getRoot().getStatementNodeList(candCrop);
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
        if(fuzzSeedVar.size()!=0)
        replaceIdentifier(fuzzSeedVar, getCropUnIdentifier(cropNodeCopy, getVarIdentifier(cropNodeCopy)));
        //替换
        NodeUtils.replace(fuzzNode, cropNodeCopy);
        //产生的新Seed
        fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzSeed.root));
        initNodeProbability(lstmPredict, fuzzNewSeed, fuzzNewSeed.root);
        getIdentifier(fuzzNewSeed);
        String res = fuzzNewSeed.getRoot().gettext();

        NodeUtils.recover(cropNodeCopy, fuzzNode);
        //System.out.println("fuzzSeed is ------" + fuzzSeed.root.gettext());
        fuzzSeed.lastUpdate = fuzzNode;
        fuzzNode.fuzzCount++;
        fuzzSeed.fuzzCount++;
        return res;


        //return "aaaaaaa";
    }

    @Override
    public void init(List<Seed> fuzzSeedList, List<Seed> cropSeedList, JSONObject configObject) {
//        this.fuzzSeed = fuzzSeed;
//        this.cropSeed = cropSeed;
        this.lstmPredict = new LSTMPredict();
        //todo
        lstmPredict.load_model();
        lstmPredict.load_data();
        for (Seed curSeed : fuzzSeedList) {
            curSeed.root.probability = 0;//set the probability of root as 0, which is not considered to be mutated
            initNodeProbability(lstmPredict, curSeed, curSeed.root);
            Sequence.clear();
            getIdentifier(curSeed);
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
            //System.out.println("11111111111111111update");
            fuzzSeedList.add(fuzzNewSeed);
            fuzzSeed.lastUpdate.fuzzCount = 0;
            K = 9;

        } else if (r == 2) {
            //System.out.println("222222222222222222update");
            fuzzSeedList.add(fuzzNewSeed);
            if (fuzzSeed.lastUpdate.fuzzCount >= 5) {
                if (fuzzSeed.Candidate.size() == 0) {
                    //换种子
                    fuzzSeedList.remove(0);
                    fuzzSeed = fuzzSeedList.get(0);
                    cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));
                    K = 0;
                }
                fuzzSeed.lastUpdate = null;
            }


        } else if (r == 3) {
            //System.out.println("3333333333333333update");
            if (fuzzSeed.lastUpdate.fuzzCount >= 5) {
                if (fuzzSeed.Candidate.size() == 0) {
                    //换种子
                    fuzzSeedList.remove(0);
                    fuzzSeed = fuzzSeedList.get(0);
                    cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));
                    K = 0;
                }
                fuzzSeed.lastUpdate = null;
            }

        } else if (r == 4) {
            //System.out.println("4444444444444444444update");
            if (fuzzSeed.lastUpdate.fuzzCount >= 5) {
                if (fuzzSeed.Candidate.size() == 0) {
                    //换种子
                    fuzzSeedList.remove(0);
                    fuzzSeed = fuzzSeedList.get(0);
                    cropSeed = cropSeedList.get(random.nextInt(cropSeedList.size()));
                    K = 0;
                }
                fuzzSeed.lastUpdate = null;
            }

        } else {
            fuzzSeedList.add(fuzzNewSeed);
            fuzzSeed.lastUpdate.fuzzCount = 0;
        }

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
            treeNode.probability = (cand.indexOf(treeNode.statement)==-1)?0:(lstmPredict.getProbability())[cand.indexOf(treeNode.statement)];

            if (seed.Candidate.size() < 5)
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

            while (treeNode != null) {
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

            while (treeNode != null) {
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

}
