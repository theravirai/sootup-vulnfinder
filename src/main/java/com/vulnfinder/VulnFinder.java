package com.vulnfinder;

import java.io.File;
import java.util.Arrays;
import java.util.Optional;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.core.util.DotExporter;
import java.nio.file.Files;
import java.nio.file.Paths;
import com.vulnfinder.checkers.HardcodedSecretChecker;
import com.vulnfinder.checkers.SqlInjectionChecker;

public class VulnFinder {
    public static void main(String[] args) {
        try {
            System.out.println("=== Bootstrapping SootUp ===");
            System.out.println("java.home: " + System.getProperty("java.home"));
            
            // 1. Identify Compiled Classes Path
            String targetPath = "build/classes/java/main";
            File targetDir = new File(targetPath);
            if (!targetDir.exists() || !targetDir.isDirectory()) {
                System.err.println("Error: Target path build/classes/java/main does not exist. Run './gradlew compileJava' first.");
                System.exit(1);
            }
            
            // 2. Set Up Input Location
            AnalysisInputLocation inputLocation = 
                new JavaClassPathAnalysisInputLocation(targetDir.getAbsolutePath());
            
            // 3. Create View
            JavaView view = new JavaView(inputLocation);
            
            // 4. Load Target Class
            var factory = view.getIdentifierFactory();
            var classType = factory.getClassType("com.vulnfinder.TargetCode");
            
            Optional<JavaSootClass> sootClassOpt = view.getClass(classType);
            if (sootClassOpt.isPresent()) {
                JavaSootClass sootClass = sootClassOpt.get();
                System.out.println("Successfully loaded class: " + sootClass.getName());
                
                // 5. Dump Methods and Jimple Bodies
                for (JavaSootMethod method : sootClass.getMethods()) {
                    System.out.println("\nMethod: " + method.getSignature());
                    if (method.getBody() != null) {
                        System.out.println("--- Jimple IR ---");
                        method.getBody().getStmts().forEach(stmt -> {
                            System.out.println("  " + stmt);
                        });
                        
                        // Export CFG for processUserData method
                        if (method.getName().equals("processUserData")) {
                            try {
                                var stmtGraph = method.getBody().getStmtGraph();
                                
                                File vizDir = new File("visualizations");
                                if (!vizDir.exists()) {
                                    vizDir.mkdirs();
                                }
                                
                                String dotContent = DotExporter.buildGraph(stmtGraph, true, new java.util.HashMap<>(), method.getSignature());
                                StringBuilder fullDot = new StringBuilder();
                                fullDot.append("digraph G {\n");
                                fullDot.append("\tcompound=true\n");
                                fullDot.append("\tlabelloc=b\n");
                                fullDot.append("\tstyle=filled\n");
                                fullDot.append("\tcolor=gray90\n");
                                fullDot.append("\tnode [shape=box,style=filled,color=white]\n");
                                fullDot.append("\tedge [fontsize=10,arrowsize=1.5,fontcolor=grey40]\n");
                                fullDot.append("\tfontsize=10\n\n");
                                fullDot.append(dotContent);
                                fullDot.append("\n}");
                                
                                Files.writeString(Paths.get("visualizations", "processUserData_cfg.dot"), fullDot.toString());
                                System.out.println("\n[INFO] CFG exported successfully to visualizations/processUserData_cfg.dot");
                                
                                String webUrl = DotExporter.createUrlToWebeditor(stmtGraph);
                                System.out.println("[INFO] Online CFG Visualization Link: " + webUrl);
                            } catch (Exception ex) {
                                System.err.println("Failed to export CFG: " + ex.getMessage());
                                ex.printStackTrace();
                            }
                        }
                    } else {
                        System.out.println("--- No Method Body (Native or Abstract) ---");
                    }
                }
                
                // Run Checkers
                HardcodedSecretChecker secretChecker = new HardcodedSecretChecker();
                secretChecker.run(view, sootClass);
                
                SqlInjectionChecker sqlChecker = new SqlInjectionChecker();
                sqlChecker.run(view, sootClass);
                
            } else {
                System.err.println("Error: Could not find class com.vulnfinder.TargetCode in view.");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
