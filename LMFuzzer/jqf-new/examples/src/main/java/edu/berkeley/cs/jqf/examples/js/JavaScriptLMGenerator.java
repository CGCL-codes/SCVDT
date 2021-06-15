package edu.berkeley.cs.jqf.examples.js;

import com.alibaba.fastjson.JSONObject;
import edu.berkeley.cs.jqf.fuzz.LM.LMGenerator;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.LSTM.LSTMPredict;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.NodeUtils;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeGet;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeNode;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.Seed;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.ngram.Model;


import java.util.*;

public class JavaScriptLMGenerator implements LMGenerator {
    private Seed fuzzSeed;
    private Seed fuzzNewSeed;
    private Seed croupSeed;
    private Seed croupNewSeed;
    private Model model;
    private List<TreeNode> fuzzSeedMaxProbabilityList = new ArrayList<>();
    private PriorityQueue<TreeNode> queue = new PriorityQueue<>();

    private Random random = new Random();


    @Override
    public String generate() {
        //return null;
//        if (fuzzSeedMaxProbabilityList.size() != 0) {
//            System.out.println("fuzzSeedMaxProbabilityList 的 大小 为 " + fuzzSeedMaxProbabilityList.size());
//            TreeNode fuzzNode = fuzzSeedMaxProbabilityList.remove(0);
//            List<TreeNode> croupSeedList = croupSeed.getRoot().getStatementNodeList(fuzzNode.getStatement());
//            if (croupSeedList.size() == 0)
//                return "var a = 1";
//            TreeNode cropNode = croupSeedList.get(random.nextInt(croupSeedList.size()));
//           TreeNode tempcropNode = TreeGet.TreeCopy(cropNode);
//            NodeUtils.replace(fuzzNode, tempcropNode);
//            //产生的新Seed
//            this.fuzzNewSeed = new Seed(TreeGet.TreeCopy(fuzzNode));
//            String res = fuzzNewSeed.getRoot().gettext();
//
//            NodeUtils.recover(tempcropNode, fuzzNode);
//            return res;
//
//
//        } else {
//            fuzzSeedMaxProbabilityList = NodeUtils.getMaxProbabilityNode(fuzzSeed.root, model, 3);
//            return "var a = 2";
//        }
//        if(fuzzSeedMaxProbabilityList.size()!=0){
//            System.out.println("    ");
//            System.out.println("fuzzSeed.root is " + fuzzSeed.root );
//            fuzzSeedMaxProbabilityList = NodeUtils.getMaxProbabilityNode(fuzzSeed.root, model, 3);
//            System.out.println("fuzzSeedMaxProbabilityList 的 大小 为 " + fuzzSeedMaxProbabilityList.size());
//            TreeNode fuzzNode = fuzzSeedMaxProbabilityList.get(random.nextInt(fuzzSeedMaxProbabilityList.size()));
//            String temp = fuzzNode.getNgram(3);
//            List<TreeNode> prepareNodeList = NodeUtils.getPrepareNode(croupSeed.root, temp,3);
//            prepareNodeList.sort((o1, o2) -> Double.compare(o2.getNodeProbability(model, 3), o1.getNodeProbability(model, 3)));
//            double maxProbability = prepareNodeList.get(0).getNodeProbability(model,3);
//            List<TreeNode> MaxNodeList = new ArrayList<>();
//            for (TreeNode i : prepareNodeList){
//                if(i.getNodeProbability(model,3)==maxProbability)
//                    MaxNodeList.add(i);
//                else
//                    break;
//            }
//
//            System.out.println("MaxPrepareNodeList 的大小 为" + MaxNodeList.size());
//            System.out.println("MaxPrepareNodeListtttttttt is " + MaxNodeList);
//
//            TreeNode cropNode = MaxNodeList.get(random.nextInt(MaxNodeList.size()));
//            NodeUtils.replace(fuzzNode, cropNode);
//            String res = fuzzSeed.getRoot().gettext();
            LSTMPredict fuzz = new LSTMPredict();
            fuzz.load_model();
            fuzz.load_data();
            List<String> list = new ArrayList<String>(Arrays.asList("program", "sourceElements", "sourceElement", "statement",
                    "iterationStatement", "expressionSequence", "singleExpression", "singleExpression", "identifier"));
            fuzz.gen_cand(list);
            System.out.println("节点的概率为：  ----- "+ Arrays.toString(fuzz.getProbability()));
            System.out.println(fuzz.getCand_list());
            return "res";
//        }
//        else{
//            LSTMPredict fuzz = new LSTMPredict();
//            fuzz.load_model();
//            fuzz.load_data();
//            List<String> list = new ArrayList<String>(Arrays.asList("program", "sourceElements", "sourceElement", "statement",
//                    "iterationStatement", "expressionSequence", "singleExpression", "singleExpression", "identifier"));
//            fuzz.gen_cand(list);
//            System.out.println("节点的概率为：  ----- "+ Arrays.toString(fuzz.getProbability()));
//            System.out.println(fuzz.getCand_list());
//            return "var a = 2";
//        }

        //利用优先队列

        /*
        this.queue = NodeUtils.getPriorityQueue(fuzzSeed.root, model,3);
        System.out.println("queue 的大小 为" + queue.size());
        System.out.println("QQQQQQQQQ is " + queue);

        TreeNode fuzzNode = queue.peek();
        String temp = fuzzNode.getNgram(3);
        List<TreeNode> prepareNodeList = NodeUtils.getPrepareNode(croupSeed.root, temp,3);
        //取概率最大的

        prepareNodeList.sort((o1, o2) -> Double.compare(o2.getNodeProbability(model, 3), o1.getNodeProbability(model, 3)));
        double maxProbability = prepareNodeList.get(0).getNodeProbability(model,3);
        List<TreeNode> MaxNodeList = new ArrayList<>();
        for (TreeNode i : prepareNodeList){
            if(i.getNodeProbability(model,3)==maxProbability)
                MaxNodeList.add(i);
            else
                break;
        }

        System.out.println("MaxNodeList 的大小 为" + MaxNodeList.size());
        System.out.println("MaxNodeListtttttttt is " + MaxNodeList);
        TreeNode cropNode = MaxNodeList.get(random.nextInt(MaxNodeList.size()));


        NodeUtils.replace(fuzzNode, cropNode);
        String res = fuzzSeed.getRoot().gettext();
        return res;*/








    }

    @Override
    public void init(List<Seed> fuzzSeedList, List<Seed> cropSeedList, JSONObject configObject ) {
        this.fuzzSeed = fuzzSeed;
        //this.croupSeed = cropSeed;
//        this.model = model;
//        this.fuzzSeedMaxProbabilityList = NodeUtils.getMaxProbabilityNode(fuzzSeed.root, model, 3);
        //this.queue = NodeUtils.getPriorityQueue(fuzzSeed.root, model,3);
        //System.out.println("MaxProbabilityList is " + fuzzSeedMaxProbabilityList);
    }

    @Override
    public void update(int r) {

    }


}