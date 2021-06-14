package com.propertygraph.graphToDot;
import org.apache.commons.cli.*;

import java.io.File;

public class Write {
    public static void main(String[] args){
                final Options options = new Options();

        {
            final Option d = new Option("d", "directory", true,
                    "target directory");
            d.setArgName("directory");
            d.setArgs(1);
            d.setRequired(true);
            options.addOption(d);
        }

        {
            final Option c = new Option("c", "ControlFlowGraph", false,
                    "control flow graph");
            c.setArgName("file");
            //c.setArgs(1);
            c.setRequired(false);
            options.addOption(c);
        }

        {
            final Option p = new Option("p", "ProgramDependencyGraph",
                    false, "program dependency graph");
            p.setArgName("file");
            //p.setArgs(1);
            p.setRequired(false);
            options.addOption(p);
        }

        {
            final Option p = new Option("a", "AbstractSyntaxTree",
                    false, "Abstract Syntax Tree");
            p.setArgName("file");
            //p.setArgs(1);
            p.setRequired(false);
            options.addOption(p);
        }

        final CommandLineParser parser = new PosixParser();
        final CommandLine cmd;
        try {
            cmd = parser.parse(options, args);
            final File target = new File(cmd.getOptionValue("d"));
            //String path = cmd.getOptionValue("d");
            if (!target.exists()) {
                System.err
                        .println("specified directory or file does not exist.");
                System.exit(0);
            }
            if (cmd.hasOption("a")) {
                SaveAST.save(target);
            }
            if (cmd.hasOption("c")){
                SaveCFG.save(target);
            }
            if (cmd.hasOption("p")){
                SavePDG.save(target);
            }
        } catch (ParseException e) {
            e.printStackTrace();
        }

    }

}
