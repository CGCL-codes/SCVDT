package edu.berkeley.cs.jqf.fuzz.LM;

import com.alibaba.fastjson.JSONObject;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.Seed;


import java.util.List;


public interface LMGenerator {
    String generate();

    void init(List<Seed> fuzzSeedList, List<Seed> cropSeedList, JSONObject configObject);

    void  update(int r);
}
