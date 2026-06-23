package com.vulnfinder.checkers;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

public class HardcodedSecretChecker {

    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern SLACK_TOKEN_PATTERN = Pattern.compile("xoxb-[0-9a-zA-Z\\-]+");

    public void run(JavaView view, JavaSootClass sootClass) {
        System.out.println("\n=== Running Hardcoded Secret Checker on " + sootClass.getName() + " ===");
        
        for (JavaSootMethod method : sootClass.getMethods()) {
            if (method.getBody() == null) continue;
            
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof JAssignStmt) {
                    JAssignStmt assignStmt = (JAssignStmt) stmt;
                    var rightOp = assignStmt.getRightOp();
                    
                    if (rightOp instanceof StringConstant) {
                        StringConstant strConstant = (StringConstant) rightOp;
                        String value = strConstant.getValue();
                        
                        Matcher awsMatcher = AWS_KEY_PATTERN.matcher(value);
                        if (awsMatcher.find()) {
                            System.out.println("[WARN] Hardcoded AWS Key detected in method " 
                                + method.getName() + ": " + awsMatcher.group());
                        }
                        
                        Matcher slackMatcher = SLACK_TOKEN_PATTERN.matcher(value);
                        if (slackMatcher.find()) {
                            System.out.println("[WARN] Hardcoded Slack Token detected in method " 
                                + method.getName() + ": " + slackMatcher.group());
                        }
                    }
                }
            }
        }
    }
}
