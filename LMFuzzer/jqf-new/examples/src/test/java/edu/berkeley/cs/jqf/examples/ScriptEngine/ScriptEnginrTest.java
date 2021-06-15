package edu.berkeley.cs.jqf.examples.ScriptEngine;


import com.pholser.junit.quickcheck.From;
import edu.berkeley.cs.jqf.examples.common.AsciiStringGenerator;
import edu.berkeley.cs.jqf.examples.js.JavaScriptCodeGenerator;
import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.Assume;
import org.junit.runner.RunWith;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

@RunWith(JQF.class)
public class ScriptEnginrTest {

    @Fuzz
    public  void testWithString( String input){
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine js = manager.getEngineByName("javascript");

        try {
            js.eval(input);
        } catch (ScriptException e) {
            Assume.assumeNoException(e);
        }

    }
    @Fuzz
    public  void debugWithString( String code){
        System.out.println("\nInput:  " + code);
        testWithString(code);
        System.out.println("Success!");

    }
    @Fuzz
    public void testWithGenerator(@From(JavaScriptCodeGenerator.class) String code) {
        testWithString(code);
    }

    @Fuzz
    public void debugWithGenerator(@From(JavaScriptCodeGenerator.class) String code) {
        debugWithString(code);
    }

}
