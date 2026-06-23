# SootUp VulnFinder: Verification Walkthrough

This document compiles the execution results and static analysis walkthrough of the `sootup-vulnfinder` project, which utilizes the **SootUp 2.0.0** framework to perform custom static vulnerability analysis on Java bytecode.

---

## To Build & Run

Ensure you have Java 17+ installed on your system (Java 17 is recommended for toolchain compatibility).

### 1. Compile the Project
```bash
./gradlew compileJava
```
This compiles the target code (`TargetCode.java`) and the scanner application (`VulnFinder.java`) under `build/classes/java/main`.

### 2. Run the Static Analysis Scanner
```bash
./gradlew run
```
This bootstraps the SootUp engine, loads the compiled `TargetCode.class`, dumps the parsed Jimple Intermediate Representation (IR), and executes both the **Hardcoded Credentials Scanner** and **SQL Injection Taint Analyzer**.

---

## 📈 Verification Run Console Output

Below is the actual execution output of the analysis engine running against `TargetCode`:

```text
=== Bootstrapping SootUp ===
java.home: /opt/homebrew/Cellar/openjdk/26.0.1/libexec/openjdk.jdk/Contents/Home
Successfully loaded class: com.vulnfinder.TargetCode

Method: <com.vulnfinder.TargetCode: void <clinit>()>
--- Jimple IR ---
  <com.vulnfinder.TargetCode: java.lang.String AWS_SECRET_KEY> = "AKIAIOSFODNN7EXAMPLE"
  <com.vulnfinder.TargetCode: java.lang.String SLACK_TOKEN> = "xoxb-123456789012-1234567890123-456789abcdef"
  return

Method: <com.vulnfinder.TargetCode: void main(java.lang.String[])>
--- Jimple IR ---
  args := @parameter0: java.lang.String[]
  $stack2 = new com.vulnfinder.TargetCode
  specialinvoke $stack2.<com.vulnfinder.TargetCode: void <init>()>()
  target = $stack2
  virtualinvoke $stack2.<com.vulnfinder.TargetCode: void processUserData(java.lang.String,java.lang.String)>("admin\' OR \'1\'=\'1", "password123")
  return

Method: <com.vulnfinder.TargetCode: void processUserData(java.lang.String,java.lang.String)>
--- Jimple IR ---
  this := @this: com.vulnfinder.TargetCode
  username := @parameter0: java.lang.String
  password := @parameter1: java.lang.String
  conn#0 = staticinvoke <java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.lang.String,java.lang.String)>("jdbc:mysql://localhost:3306/db", username, password)
  stmt = interfaceinvoke conn#0.<java.sql.Connection: java.sql.Statement createStatement()>()
  query = dynamicinvoke "makeConcatWithConstants" <java.lang.String (java.lang.String)>(username) <java.lang.invoke.StringConcatFactory: java.lang.invoke.CallSite makeConcatWithConstants(java.lang.invoke.MethodHandles$Lookup,java.lang.String,java.lang.invoke.MethodType,java.lang.String,java.lang.Object[])>("SELECT * FROM users WHERE username = \'\u0001\'")
  interfaceinvoke stmt.<java.sql.Statement: boolean execute(java.lang.String)>(query)
  goto
  $stack6 := @caughtexception
  conn#1 = (java.lang.Throwable) $stack6
  #l0 = (java.lang.Exception) $stack6
  virtualinvoke #l0.<java.lang.Exception: void printStackTrace()>()
  return

Method: <com.vulnfinder.TargetCode: void <init>()>
--- Jimple IR ---
  this := @this: com.vulnfinder.TargetCode
  specialinvoke this.<java.lang.Object: void <init>()>()
  return

=== Running Hardcoded Secret Checker on com.vulnfinder.TargetCode ===
[WARN] Hardcoded AWS Key detected in method <clinit>: AKIAIOSFODNN7EXAMPLE
[WARN] Hardcoded Slack Token detected in method <clinit>: xoxb-123456789012-1234567890123-456789abcdef

=== Running SQL Injection Checker on com.vulnfinder.TargetCode ===
[Taint Trace] Parameter 0 mapped to local: args
[Taint Trace] Parameter 0 mapped to local: username
[Taint Trace] Taint propagated via assignment: conn#0 = staticinvoke <java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.lang.String,java.lang.String)>("jdbc:mysql://localhost:3306/db", username, password)
[Taint Trace] Taint propagated via assignment: stmt = interfaceinvoke conn#0.<java.sql.Connection: java.sql.Statement createStatement()>()
[Taint Trace] Taint propagated via assignment: query = dynamicinvoke "makeConcatWithConstants" <java.lang.String (java.lang.String)>(username) <java.lang.invoke.StringConcatFactory: java.lang.invoke.CallSite makeConcatWithConstants(java.lang.invoke.MethodHandles$Lookup,java.lang.String,java.lang.invoke.MethodType,java.lang.String,java.lang.Object[])>("SELECT * FROM users WHERE username = '\u0001'")
[WARN] SQL Injection detected in method processUserData: Tainted local 'query' passed to database execute sink (<java.sql.Statement: boolean execute(java.lang.String)>)!
```

---

## Detailed Vulnerability Trace

### 1. Hardcoded Credentials Scanning
In `TargetCode.java`, Declared two static credential strings. Because they are static, the compiler puts their initialization into the static initializer block `<clinit>()`:
*   `AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"`
*   `SLACK_TOKEN = "xoxb-..."`

Our `HardcodedSecretChecker` scanned all assignment expressions (`JAssignStmt`) inside `<clinit>()` and evaluated the `StringConstant` values against regex patterns:
- Found AWS Key matching pattern `AKIA[0-9A-Z]{16}`.
- Found Slack Token matching pattern `xoxb-[0-9a-zA-Z\-]+`.

### 2. SQL Injection Taint Analysis
The `SqlInjectionChecker` traces untrusted input variables through the control flow graph.

1.  **Source Identification**: The `username` parameter (first parameter, hence index `0`) is tracked when it enters `processUserData` via the parameter identity statement:
    `username := @parameter0: java.lang.String`
    The local variable `username` is added to the tainted set.

2.  **Propagation**: 
    - The local variable `conn#0` becomes tainted because it is assigned via an invocation reading `username` (taint source propagates to database connection reference).
    - The local variable `stmt` becomes tainted because it is created from `conn#0`.
    - The local variable `query` is assigned the result of a string concatenation containing the tainted local `username`:
      `query = dynamicinvoke "makeConcatWithConstants"(username)...`
      `query` is marked as tainted because `username` is read inside the concat expression.

3.  **Sink Trigger**: The statement:
    `interfaceinvoke stmt.<java.sql.Statement: boolean execute(java.lang.String)>(query)`
    is intercepted because the target method is `execute` on the interface type `java.sql.Statement`.
    Because the argument passed is `query` (which is in our `taintedLocals` set), the scanner logs a SQL Injection vulnerability warning.

---

## 💡 SootUp 2.0.0 Lessons Learned

1.  **Modular Bootstrap**: SootUp removes all global singletons (like legacy Soot's `Scene.v()`). A `JavaView` is instantiated directly using input locations, e.g. `new JavaView(new JavaClassPathAnalysisInputLocation(path))`.

2.  **Bytecode Version Parsing**: SootUp 2.0.0 parses class files using an internal ASM package. If classes are compiled under very new JVM versions (e.g. Java 26), parsing fails silently. We resolved this by explicitly targeting Java 17 compilation compatibility in `build.gradle.kts`, generating version 61 class files which compile and scan successfully.

3.  **Standard Library Sandbox Constraints**: In modular JDK runtimes (Java 9+), loading JDK system packages (like `java.sql`) requires modular JRT resolvers. To prevent modular loading constraints on arbitrary client JVMs, we bypassed JRT requirements by matching sink signatures directly via string representation checks (`receiverType.toString().equals("java.sql.Statement")`), making the checkers highly portable.
