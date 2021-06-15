package edu.berkeley.cs.jqf.fuzz.LM;




import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.junit.runner.Result;



import java.io.File;
import java.lang.reflect.Constructor;
import java.time.Duration;

public class VainDriver {
    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: java " + edu.berkeley.cs.jqf.fuzz.LM.LMDriver.class + " TEST_CLASS TEST_METHOD GENERATOR_CLASS [OUTPUT_DIR]");
            System.exit(1);
        }

        String testClassName = args[0];
        String testMethodName = args[1];
        String genClassName  = args[2];
        String SeedDir = args[3];

        String outputDirectoryName = args.length > 4 ? args[4] : "fuzz-results";
        File outputDirectory = new File(outputDirectoryName);
        try {
            Duration duration = Duration.parse("PT600s");
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
            System.out.println(gen);
            Guidance guidance = new vainGuidance(gen, title, null, outputDirectory,SeedDir);

            Result res = GuidedFuzzing.run(testClassName, testMethodName, guidance, System.out);
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
