package edu.berkeley.cs.jqf.examples.js;

import com.alibaba.fastjson.JSONObject;
import edu.berkeley.cs.jqf.fuzz.LM.LMGenerator;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.Seed;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.Random;

public class VainGenerator implements LMGenerator {
    private Random r = new Random();
    public int i=0;
    public File[] seeds;

    public String generate()  {

        String res="";
        try{
        FileReader fileReader = new FileReader(seeds[i++]);
        BufferedReader reader = new BufferedReader(fileReader);
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line + '\n');
        }
        reader.close();
        res= sb.toString();}
        catch (IOException e){}
        return res;
    }

    public void update(int a){
    }
    public void init(List<Seed> fuzzSeedList, List<Seed> cropSeedList, JSONObject configObject){
        this.seeds = new File("/data/WYC/xyf/suite").listFiles();
        System.out.println(seeds.length);
    };

}
