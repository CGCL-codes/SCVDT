package edu.berkeley.cs.jqf.fuzz.LM;



import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.ParseToSeedUtils;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate.Seed;
import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.ngram.Model;
import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.guidance.TimeoutException;
import edu.berkeley.cs.jqf.fuzz.util.Coverage;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import org.apache.commons.io.FileUtils;



import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class vainGuidance implements Guidance {
    private  LMGenerator generator;

    protected Thread appThread;

    protected Random random = new Random() ;

    /**测试方法名*/
    public final  String testName;
    /**测试最长时间*/
    public final  long maxDurationMillis;

    /** The directory where fuzzing results are written. */
    protected final File outputDirectory;

    /** The directory where saved inputs are written. */
    protected File savedInputsDirectory;

    /** The directory where saved inputs are written. */
    protected File savedFailuresDirectory;

    /** The file where log data is written. */
    protected File logFile;

    /** The file where saved plot data is written. */
    protected File statsFile;

    /**  trials 数量 */
    protected long numTrials = 0;

    /**  valid inputs 数量 */
    protected long numValid = 0;

    /** Coverage statistics for a single run.一次运行的覆盖范围统计信息 */
    protected Coverage runCoverage = new Coverage();

    /** Cumulative coverage statistics. 累积覆盖率统计 */
    protected Coverage totalCoverage = new Coverage();

    /** Cumulative coverage for valid inputs.  有效输入的累积覆盖率*/
    protected Coverage validCoverage = new Coverage();

    /** Number of conditional jumps since last run was started.上次运行以来的条件跳转次数*/
    protected long branchCount;

    protected Set<Integer> uniqueValidInputs = new HashSet<>();

    /** Unique paths for valid inputs */
    protected Set<Integer> uniquePaths = new HashSet<>();

    /** Unique branch sets for valid inputs */
    protected Set<Integer> uniqueBranchSets = new HashSet<>();


    /** The set of unique failures found so far. */
    protected Set<List<StackTraceElement>> uniqueFailures = new HashSet<>();

    /** Minimum amount of time (in millis) between two stats refreshes. 两次统计刷新之间的最短时间（以毫秒为单位）*/
    protected static final long STATS_REFRESH_TIME_PERIOD = 300;



    /**  开始时间*/
    public final Date startTime = new Date();

    /** Time at last stats refresh. */
    protected Date lastRefreshTime = startTime;

    /** Total execs at last stats refresh. */
    protected long lastNumTrials = 0;

    /** Date when last run was started.上次运行开始的日期。 */
    protected Date runStart;

    /** Timeout for an individual run. 单个运行超时 时间*/
    protected long singleRunTimeoutMillis;

    /** 系统控制台 */
    protected final Console console = System.console();
    /** 当前产生输入 */
    public String currentInput ;

    /**   js fuzz文件列表*/
    public List<Seed> fuzzSeedList = new ArrayList<>();

    public List<Seed> cropSeedList = new ArrayList<>();

    public int filecount;





    public vainGuidance(LMGenerator generator, String testName, Duration duration, File outputDirectory, String SeedDir) throws IOException {
        this.filecount=0;
        this.generator = generator;
        this.testName = testName;
        this.maxDurationMillis =duration!=null?duration.toMillis():Long.MAX_VALUE;
        this.outputDirectory = outputDirectory;
        prepareOutputDirectory();
        File seedInputDir = new File(SeedDir);
        System.out.println(SeedDir);
       if (!seedInputDir.isDirectory()) {
            throw new IllegalArgumentException(String.format("%s is not a directory", seedInputDir));
        }
        System.out.println("guidance");
        File[] seedInputFiles = seedInputDir.listFiles();
        List<Seed> a=null;
        List<Seed> b=null;
        JSONObject c=null;
        this.generator.init(a,b,c);
    }
    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        runCoverage.clear();
        currentInput = generator.generate();
        return new ByteArrayInputStream(currentInput.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public boolean hasInput() {
        Date nowTime = new Date();
        long escapeTime = nowTime.getTime() - startTime.getTime();
        return escapeTime<maxDurationMillis;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        // Stop timeout handling
        this.runStart = null;

        // Increment run count
        this.numTrials++;

        boolean valid = result == Result.SUCCESS;

        if (valid) {
            numValid++;
        }

        if (result == Result.SUCCESS || result == Result.INVALID) {

            try{
            BufferedWriter out = new BufferedWriter(new FileWriter("/home/user/xyf/die_js/normal/"+(filecount++)+".js"));
            out.write(currentInput);
            out.close();}
            catch(Exception e){
            }
            // Coverage before
            int nonZeroBefore = totalCoverage.getNonZeroCount();
            int validNonZeroBefore = validCoverage.getNonZeroCount();

            // Update total coverage
            boolean coverageBitsUpdated = totalCoverage.updateBits(runCoverage);

            int nonZeroAfter = totalCoverage.getNonZeroCount();

            if (valid) {
                validCoverage.updateBits(runCoverage);
                if (!uniqueValidInputs.contains(currentInput.hashCode())) {
                    uniqueValidInputs.add(currentInput.hashCode());

                    uniquePaths.add(runCoverage.hashCode());
                    boolean has_new_branches_covered = uniqueBranchSets.add(runCoverage.nonZeroHashCode());

                    // Greybox: only reward for inputs that cover new branches
                    if (has_new_branches_covered) {
                        //generator.update(20);
                        generator.update(1);
                    } else {
                        //generator.update(0);
                        generator.update(2);
                    }
                }
                else{
                    generator.update(3);
                }

            } else {
                // TODO: allow this to be customizable
                //generator.update(0);
                generator.update(4);
            }




            // Coverage after

            int validNonZeroAfter = validCoverage.getNonZeroCount();

            if (nonZeroAfter > nonZeroBefore || validNonZeroAfter > validNonZeroBefore) {
//            try {
//                saveCurrentInput(valid);
//            } catch (IOException e) {
//                throw new GuidanceException(e);
//            }
            }


        }else if (result == Result.FAILURE || result == Result.TIMEOUT) {
            try{
                BufferedWriter out = new BufferedWriter(new FileWriter("/home/user/xyf/die_js/failure/"+(filecount++)+".js"));
                out.write(currentInput);
                out.close();}
            catch(Exception e){
            }
            String msg = error.getMessage();

            // Get the root cause of the failure
            Throwable rootCause = error;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }

            // Attempt to add this to the set of unique failures
            if (uniqueFailures.add(Arrays.asList(rootCause.getStackTrace()))) {
                generator.update(1);

                // Save crash to disk
//                try {
//                    saveCurrentFailure();
//                } catch (IOException e) {
//                    throw new GuidanceException(e);
//                }

            }
            else{
                generator.update(3);
            }

        }

        displayStats();

    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        if (appThread != null) {
            throw new IllegalStateException(ZestGuidance.class +
                    " only supports single-threaded apps at the moment");
        }
        appThread = thread;

        return this::handleEvent;
    }

    /** Handles a trace event generated during test execution */
    protected void handleEvent(TraceEvent e) {
        // Collect totalCoverage
        runCoverage.handleEvent(e);
        // Check for possible timeouts every so often
        if (this.singleRunTimeoutMillis > 0 &&
                this.runStart != null && (++this.branchCount) % 10_000 == 0) {
            long elapsed = new Date().getTime() - runStart.getTime();
            if (elapsed > this.singleRunTimeoutMillis) {
                throw new TimeoutException(elapsed, this.singleRunTimeoutMillis);
            }
        }
    }

    private void prepareOutputDirectory() throws IOException {

        // Create the output directory if it does not exist
        if (!outputDirectory.exists()) {
            if (!outputDirectory.mkdirs()) {
                throw new IOException("Could not create output directory" +
                        outputDirectory.getAbsolutePath());
            }
        }

        // Make sure we can write to output directory
        if (!outputDirectory.isDirectory() || !outputDirectory.canWrite()) {
            throw new IOException("Output directory is not a writable directory: " +
                    outputDirectory.getAbsolutePath());
        }

        // Name files and directories after AFL
        this.savedInputsDirectory = new File(outputDirectory, "corpus");
        this.savedInputsDirectory.mkdirs();
        this.savedFailuresDirectory = new File(outputDirectory, "failures");
        this.savedFailuresDirectory.mkdirs();
        this.statsFile = new File(outputDirectory, "plot_data");
        this.logFile = new File(outputDirectory, "fuzz.log");


        // Delete everything that we may have created in a previous run.
        // Trying to stay away from recursive delete of parent output directory in case there was a
        // typo and that was not a directory we wanted to nuke.
        // We also do not check if the deletes are actually successful.
        statsFile.delete();
        logFile.delete();
        for (File file : savedInputsDirectory.listFiles()) {
            file.delete();
        }
        for (File file : savedFailuresDirectory.listFiles()) {
            file.delete();
        }

        appendLineToFile(statsFile, "# unix_time, unique_crashes, total_cov, valid_cov, total_inputs, valid_inputs, valid_paths, valid_branch_sets, unique_valid_inputs");
    }
    private void appendLineToFile(File file, String line) throws GuidanceException {
        try (PrintWriter out = new PrintWriter(new FileWriter(file, true))) {
            out.println(line);
        } catch (IOException e) {
            throw new GuidanceException(e);
        }

    }
    protected String getTitle() {
        return  "LM Fuzzing\n" +
                "--------------------\n";
    }
    private void displayStats(){
        displayStats(false);
    }

    // Call only if console exists
    private void displayStats(boolean force) {

        Date now = new Date();
        long intervalMilliseconds = now.getTime() - lastRefreshTime.getTime();
        if (!force && intervalMilliseconds < STATS_REFRESH_TIME_PERIOD) {
            return;
        }
        long interlvalTrials = numTrials - lastNumTrials;
        long intervalExecsPerSec = interlvalTrials * 1000L / intervalMilliseconds;
        double intervalExecsPerSecDouble = interlvalTrials * 1000.0 / intervalMilliseconds;
        lastRefreshTime = now;
        lastNumTrials = numTrials;
        long elapsedMilliseconds = now.getTime() - startTime.getTime();
        long execsPerSec = numTrials * 1000L / elapsedMilliseconds;


        int nonZeroCount = totalCoverage.getNonZeroCount();
        double nonZeroFraction = nonZeroCount * 100.0 / totalCoverage.size();
        int nonZeroValidCount = validCoverage.getNonZeroCount();
        double nonZeroValidFraction = nonZeroValidCount * 100.0 / validCoverage.size();

        if (console != null ){
            console.printf("\033[2J");
            console.printf("\033[H");
            console.printf(this.getTitle() + "\n");
            if (this.testName != null) {
                console.printf("Test name:            %s\n", this.testName);
            }
            console.printf("Results directory:    %s\n", this.outputDirectory.getAbsolutePath());
            console.printf("Elapsed time:         %s (%s)\n", millisToDuration(elapsedMilliseconds),
                    maxDurationMillis == Long.MAX_VALUE ? "no time limit" : ("max " + millisToDuration(maxDurationMillis)));
            console.printf("Number of executions: %,d\n", numTrials);
            console.printf("Valid inputs:         %,d (%.2f%%)\n", numValid, numValid*100.0/numTrials);
            console.printf("Unique failures:      %,d\n", uniqueFailures.size());
            console.printf("Execution speed:      %,d/sec now | %,d/sec overall\n", intervalExecsPerSec, execsPerSec);
            console.printf("Total coverage:       %,d branches (%.2f%% of map)\n", nonZeroCount, nonZeroFraction);
            console.printf("Valid coverage:       %,d branches (%.2f%% of map)\n", nonZeroValidCount, nonZeroValidFraction);
            console.printf("Unique valid inputs:  %,d (%.2f%%)\n", uniqueValidInputs.size(),
                    uniqueValidInputs.size()*100.0/numTrials);
            console.printf("Unique valid paths:   %,d \n", uniquePaths.size());
            console.printf("''  non-zero paths:   %,d \n", uniqueBranchSets.size());
        }

        String plotData = String.format("%d, %d, %d, %d, %d, %d, %d, %d, %d",
                TimeUnit.MILLISECONDS.toSeconds(now.getTime()), uniqueFailures.size(), nonZeroCount, nonZeroValidCount,
                numTrials, numValid, uniquePaths.size(), uniqueBranchSets.size(), uniqueValidInputs.size());
        appendLineToFile(statsFile, plotData);

    }

    private String millisToDuration(long millis) {
        long seconds = TimeUnit.MILLISECONDS.toSeconds(millis % TimeUnit.MINUTES.toMillis(1));
        long minutes = TimeUnit.MILLISECONDS.toMinutes(millis % TimeUnit.HOURS.toMillis(1));
        long hours = TimeUnit.MILLISECONDS.toHours(millis);
        String result = "";
        if (hours > 0) {
            result = hours + "h ";
        }
        if (hours > 0 || minutes > 0) {
            result += minutes + "m ";
        }
        result += seconds + "s";
        return result;
    }

}
