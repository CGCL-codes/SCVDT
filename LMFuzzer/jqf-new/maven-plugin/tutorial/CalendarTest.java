import java.util.*;
import static java.util.GregorianCalendar.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

import org.junit.runner.RunWith;
import com.pholser.junit.quickcheck.*;
import com.pholser.junit.quickcheck.generator.*;
import edu.berkeley.cs.jqf.fuzz.*;

@RunWith(JQF.class)
public class CalendarTest {

    @Fuzz
    public void testLeapYear(@From(CalendarGenerator.class) GregorianCalendar cal) {
        // Assume that the date is Feb 29
        assumeTrue(cal.get(MONTH) == FEBRUARY);
        assumeTrue(cal.get(DAY_OF_MONTH) == 29);

        // Under this assumption, validate leap year rules
        assertTrue(cal.get(YEAR) + " should be a leap year", CalendarLogic.isLeapYear(cal));
    }

    @Fuzz
    public void testCompare(@Size(max=100) List<@From(CalendarGenerator.class) GregorianCalendar> cals) {
        // Sort list of calendar objects using our custom comparator function
        Collections.sort(cals, CalendarLogic::compare);

        // If they have an ordering, then the sort should succeed
        for (int i = 1; i < cals.size(); i++) {
            Calendar c1 = cals.get(i-1);
            Calendar c2 = cals.get(i);
            assumeFalse(c1.equals(c2)); // Assume that we have distinct dates
            assertTrue(c1 + " should be before " + c2, c1.before(c2));  // Then c1 < c2
        }
    }
}
