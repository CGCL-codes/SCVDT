package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.LSTM;

import edu.berkeley.cs.jqf.fuzz.LM.LMDriver;
import edu.berkeley.cs.jqf.fuzz.LM.LMGenerator;
import edu.berkeley.cs.jqf.fuzz.LM.LMGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.junit.runner.Result;

import java.io.File;
import java.lang.reflect.Constructor;
import java.time.Duration;

public class LSTMDriver {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java " + LMDriver.class + " TEST_CLASS TEST_METHOD GENERATOR_CLASS [OUTPUT_DIR]");
            System.exit(1);
        }

        String testClassName = args[0];
        String testMethodName = args[1];
        String genClassName  = args[2];

        String outputDirectoryName = args.length > 3 ? args[3] : "fuzz-results";
        File outputDirectory = new File(outputDirectoryName);
        try {
            Duration duration = Duration.parse("PT100s");
            for (int i = 0; i < 100; i++) {

                System.out.println("duration:  " + duration);
            }

            Class<?> clazz = Class.forName(genClassName);
            System.out.println(clazz.toString());
            Constructor<?> clazzConstructor = clazz.getConstructor();
            System.out.println(clazzConstructor);
            LMGenerator gen = (LMGenerator) clazzConstructor.newInstance();

            // Load the guidance
            String title = testClassName + "#" + testMethodName;
            Guidance guidance = new LSTMGuidance(gen, title, duration, outputDirectory);

            Result res = GuidedFuzzing.run(testClassName, testMethodName, guidance, System.out);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
