package com.vulnfinder;

import java.io.File;
import java.util.Arrays;
import java.util.Optional;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
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
