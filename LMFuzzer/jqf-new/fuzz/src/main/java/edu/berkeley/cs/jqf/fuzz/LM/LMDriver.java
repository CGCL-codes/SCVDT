package edu.berkeley.cs.jqf.fuzz.LM;




import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.junit.runner.Result;



import java.io.File;
import java.lang.reflect.Constructor;
import java.time.Duration;

public class LMDriver {
    public static void main(String[] args) {
        if (args.length < 5) {
            System.err.println("Usage: java " + LMDriver.class + " TEST_CLASS TEST_METHOD GENERATOR_CLASS [OUTPUT_DIR]");
            System.exit(1);
        }

        String testClassName = args[0];
        String testMethodName = args[1];
        String genClassName  = args[2];
        String SeedDir = args[3];
        String CropDir = args[4];

        String outputDirectoryName = args.length > 5 ? args[5] : "fuzz-results";
        File outputDirectory = new File(outputDirectoryName);
        try {
            Duration duration = Duration.parse("PT3h");
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
            Guidance guidance = new LMGuidance(gen, title, null, outputDirectory,SeedDir,CropDir);

            Result res = GuidedFuzzing.run(testClassName, testMethodName, guidance, System.out);
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
