/*
 * Copyright (c) 2017-2018 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.berkeley.cs.jqf.examples.closure;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.logging.LogManager;

import com.google.javascript.jscomp.CompilationLevel;
import com.google.javascript.jscomp.Compiler;
import com.google.javascript.jscomp.CompilerOptions;
import com.google.javascript.jscomp.Result;
import com.google.javascript.jscomp.SourceFile;
import com.pholser.junit.quickcheck.From;
import edu.berkeley.cs.jqf.examples.common.AsciiStringGenerator;
import edu.berkeley.cs.jqf.examples.js.JavaScriptCodeGenerator;
import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.apache.commons.io.IOUtils;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(JQF.class)
public class CompilerTest {

    static {
        // Disable all logging by Closure passes
        LogManager.getLogManager().reset();
    }

    private Compiler compiler = new Compiler(new PrintStream(new ByteArrayOutputStream(), false));
    private CompilerOptions options = new CompilerOptions();
    private SourceFile externs = SourceFile.fromCode("externs", "");

    @Before
    public void initCompiler() {
        // Don't use threads
        compiler.disableThreads();
        // Don't print things
        options.setPrintConfig(false);
        // Enable all safe optimizations
        CompilationLevel.SIMPLE_OPTIMIZATIONS.setOptionsForCompilationLevel(options);
    }

    private void doCompile(SourceFile input) {
        Result result = compiler.compile(externs, input, options);
        Assume.assumeTrue(result.success);
    }

    @Fuzz
    public void testWithString(@From(AsciiStringGenerator.class) String code) {

       // System.out.println("current input is  "+ code);
        SourceFile input = SourceFile.fromCode("input", code);
        doCompile(input);
    }

    @Fuzz
    public void debugWithString(@From(AsciiStringGenerator.class) String code) {
        System.out.println("\nInput:  " + code);
        testWithString(code);
        System.out.println("Output: " + compiler.toSource());
    }

    @Test
    public void smallTest() {
        debugWithString("x <<= Infinity");
    }

    @Fuzz
    public void testWithInputStream(InputStream in) throws IOException {
        SourceFile input = SourceFile.fromInputStream("input", in, StandardCharsets.UTF_8);
        doCompile(input);
    }

    @Fuzz
    public void debugWithInputStream(InputStream in) throws IOException {
        String input = IOUtils.toString(in, StandardCharsets.UTF_8);
        debugWithString(input);
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
