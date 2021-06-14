package com.platform.demo.service;

import com.propertygraph.pe.MethodInfo;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Common {
    static public List<File> getFiles(File file) {
        final List<File> files = new ArrayList<File>();
        if (file.isFile() && file.getName().endsWith(".java")) {
            files.add(file);
        } else if (file.isDirectory()) {
            for (final File child : file.listFiles()) {
                final List<File> children = getFiles(child);
                files.addAll(children);
            }
        }
        return files;
    }

    static public String getMethodSignature(final MethodInfo method) {

        final StringBuilder text = new StringBuilder();

        text.append(method.name);
        text.append(" <");
        text.append(method.startLine);
        text.append("...");
        text.append(method.endLine);
        text.append(">");

        return text.toString();
    }
}