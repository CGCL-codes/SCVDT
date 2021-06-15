//package edu.berkeley.cs.jqf.examples.htmlparser;
//
//
//import com.pholser.junit.quickcheck.From;
//import edu.berkeley.cs.jqf.examples.common.AsciiStringGenerator;
//import edu.berkeley.cs.jqf.examples.common.Dictionary;
//import edu.berkeley.cs.jqf.examples.xml.XMLDocumentUtils;
//import edu.berkeley.cs.jqf.examples.xml.XmlDocumentGenerator;
//import edu.berkeley.cs.jqf.fuzz.Fuzz;
//import edu.berkeley.cs.jqf.fuzz.JQF;
//import org.htmlparser.util.ParserException;
//import org.junit.Assume;
//import org.junit.runner.RunWith;
//import org.htmlparser.Parser;
//import org.w3c.dom.Document;
//
//
//@RunWith(JQF.class)
//public class htmlparsertest {
//
//
//    @Fuzz
//    public void testWithString(@From(AsciiStringGenerator.class) String input) {
//        try {
//            Parser parser= new Parser(input);
//        } catch (ParserException e) {
//            Assume.assumeNoException(e);
//        }
//
//    }
//
//    @Fuzz
//    public void debugWithString(@From(AsciiStringGenerator.class) String code) {
//        System.out.println("\nInput:  " + code);
//        testWithString(code);
//        System.out.println("Success!");
//    }
//
//    @Fuzz
//    public void testWithGenerator(@From(XmlDocumentGenerator.class)
//                                  @Dictionary("dictionaries/ant-project.dict") Document dom) {
//        testWithString(XMLDocumentUtils.documentToString(dom));
//    }
//
//    @Fuzz
//    public void debugWithGenerator(@From(XmlDocumentGenerator.class)
//                                   @Dictionary("dictionaries/ant-project.dict") Document dom) {
//        System.out.println(XMLDocumentUtils.documentToString(dom));
//        testWithGenerator(dom);
//    }
//}
