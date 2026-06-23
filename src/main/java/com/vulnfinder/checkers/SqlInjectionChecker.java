package com.vulnfinder.checkers;

import java.util.HashSet;
import java.util.Set;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.typehierarchy.TypeHierarchy;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

public class SqlInjectionChecker {

    public void run(JavaView view, JavaSootClass sootClass) {
        System.out.println("\n=== Running SQL Injection Checker on " + sootClass.getName() + " ===");
        
        for (JavaSootMethod method : sootClass.getMethods()) {
            if (method.getBody() == null) continue;
            
            Set<String> taintedLocals = new HashSet<>();
            
            for (Stmt stmt : method.getBody().getStmts()) {
                // 1. Trace Sources (Method parameter 0, e.g. username)
                if (stmt instanceof JIdentityStmt) {
                    JIdentityStmt identityStmt = (JIdentityStmt) stmt;
                    String rightOpStr = identityStmt.getRightOp().toString();
                    
                    // Taint parameter 0 (usually the username or first arg)
                    if (rightOpStr.startsWith("@parameter0")) {
                        String localName = identityStmt.getLeftOp().getName();
                        taintedLocals.add(localName);
                        System.out.println("[Taint Trace] Parameter 0 mapped to local: " + localName);
                    }
                }
                
                // 2. Propagate Taint via Assignment
                if (stmt instanceof JAssignStmt) {
                    JAssignStmt assignStmt = (JAssignStmt) stmt;
                    var leftOp = assignStmt.getLeftOp();
                    var rightOp = assignStmt.getRightOp();
                    
                    if (leftOp instanceof Local) {
                        String leftName = ((Local) leftOp).getName();
                        
                        // If RHS reads any tainted local, LHS becomes tainted
                        boolean readsTainted = rightOp.getUses().anyMatch(val -> 
                            val instanceof Local && taintedLocals.contains(((Local) val).getName())
                        );
                        
                        if (readsTainted) {
                            taintedLocals.add(leftName);
                            System.out.println("[Taint Trace] Taint propagated via assignment: " + leftName + " = " + rightOp);
                        } else {
                            // If it's overwritten with clean value, untaint it
                            if (taintedLocals.contains(leftName)) {
                                taintedLocals.remove(leftName);
                                System.out.println("[Taint Trace] Local untainted (overwritten): " + leftName);
                            }
                        }
                    }
                }
                
                // 3. Detect Sinks
                AbstractInvokeExpr invokeExpr = null;
                if (stmt instanceof JInvokeStmt) {
                    invokeExpr = ((JInvokeStmt) stmt).getInvokeExpr().orElse(null);
                } else if (stmt instanceof JAssignStmt) {
                    invokeExpr = ((JAssignStmt) stmt).getInvokeExpr().orElse(null);
                }
                
                if (invokeExpr != null) {
                    var sig = invokeExpr.getMethodSignature();
                    ClassType receiverType = sig.getDeclClassType();
                    String methodName = sig.getName();
                    
                    boolean isSinkMethod = methodName.equals("execute") 
                        || methodName.equals("executeQuery") 
                        || methodName.equals("executeUpdate") 
                        || methodName.equals("executeLargeUpdate");
                    
                    boolean isStatementSink = receiverType.toString().equals("java.sql.Statement") 
                        || receiverType.toString().equals("java.sql.PreparedStatement");
                    
                    if (isSinkMethod && isStatementSink) {
                        // Check if any argument is tainted
                        for (var arg : invokeExpr.getArgs()) {
                            if (arg instanceof Local) {
                                Local localArg = (Local) arg;
                                if (taintedLocals.contains(localArg.getName())) {
                                    System.out.println("[WARN] SQL Injection detected in method " 
                                        + method.getName() + ": Tainted local '" + localArg.getName() 
                                        + "' passed to database execute sink (" + sig + ")!");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
