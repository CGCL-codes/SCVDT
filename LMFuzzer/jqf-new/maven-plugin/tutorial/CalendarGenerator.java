import java.util.GregorianCalendar;
import java.util.TimeZone;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

import static java.util.GregorianCalendar.*;

public class CalendarGenerator extends Generator<GregorianCalendar> {

    public CalendarGenerator() {
        super(GregorianCalendar.class); // Register the type of objects that we can create
    }

    // This method is invoked to generate a single test case
    @Override
    public GregorianCalendar generate(SourceOfRandomness random, GenerationStatus __ignore__) {
        // Initialize a calendar object
        GregorianCalendar cal = new GregorianCalendar();
        cal.setLenient(true); // This allows invalid dates to silently wrap (e.g. Apr 31 ==> May 1).

        // Randomly pick a day, month, and year
        cal.set(DAY_OF_MONTH, random.nextInt(31) + 1); // a number between 1 and 31 inclusive
        cal.set(MONTH, random.nextInt(12) + 1); // a number between 1 and 12 inclusive
        cal.set(YEAR, random.nextInt(cal.getMinimum(YEAR), cal.getMaximum(YEAR)));

        // Optionally also pick a time
        if (random.nextBoolean()) {
            cal.set(HOUR, random.nextInt(24));
            cal.set(MINUTE, random.nextInt(60));
            cal.set(SECOND, random.nextInt(60));
        }

        // Let's set a timezone
        // First, get supported timezone IDs (e.g. "America/Los_Angeles")
        String[] allTzIds = TimeZone.getAvailableIDs();

        // Next, choose one randomly from the array
        String tzId = random.choose(allTzIds);
        TimeZone tz = TimeZone.getTimeZone(tzId);

        // Assign it to the calendar
        cal.setTimeZone(tz);

	// Return the randomly generated calendar object
        return cal;
    }
}
