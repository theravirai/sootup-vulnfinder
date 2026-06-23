# Concept: Jimple Intermediate Representation (IR)

## Definition
**Jimple** is the primary intermediate representation used by SootUp. It is a **typed, 3-address, statement-based representation** designed to simplify program analysis. 

Rather than analyzing raw JVM bytecode (which is stack-based and contains over 200 instruction types) or Java source code (which has complex syntax and nesting), SootUp translates them into Jimple. 

---

## Why It Matters in Static Analysis
Analyzing stack-based bytecode directly is difficult because values are pushed and popped implicitly. For example, to know where a variable came from, you must track the stack state. 

Jimple eliminates the stack by:
1.  **Introducing Explicit Local Variables**: All stack operations are converted to assignments on explicit local variables (e.g., `temp$0`).
2.  **Linearizing Expressions**: Nested expressions are broken down so that each statement performs at most one operation (3-address format).

### Nested Expression Reduction
**Java Source:**
```java
int result = obj.calculate(x) + getOffset();
```

**Equivalent Jimple IR:**
```jimple
temp$0 = virtualinvoke obj.<com.example.MyClass: int calculate(int)>(x);
temp$1 = virtualinvoke this.<com.example.MyClass: int getOffset()>();
result = temp$0 + temp$1;
```

---

## Common SootUp Jimple Statements
SootUp represents Jimple statements with specific classes under the `sootup.core.jimple.common.stmt` package.

### 1. `JIdentityStmt`
Used to bind method parameters and the `this` reference to local variables at the beginning of a method body.
*   **Format**: `local_variable := @parameterX: Type;` or `local_variable := @this: Type;`
*   **Example**: 
    ```jimple
    this := @this: com.vulnfinder.TargetCode;
    username := @parameter0: java.lang.String;
    ```

### 2. `JAssignStmt`
Represents an assignment of a value or expression to a variable or field.
*   **Format**: `variable = expression;`
*   **Example**:
    ```jimple
    query = "SELECT * FROM users WHERE username = 'admin'";
    ```

### 3. `JInvokeStmt`
Represents a method invocation when the return value is ignored. (If the return value is assigned, it is represented as a `JAssignStmt` whose right-hand side is an invoke expression).
*   **Format**: `invoke_type object.<method_signature>(arguments);`
*   **Example**:
    ```jimple
    virtualinvoke stmt.<java.sql.Statement: boolean execute(java.lang.String)>(query);
    ```

### 4. `JIfStmt` & `JGotoStmt`
Control-flow branching statements. `JIfStmt` contains a condition and a target label, while `JGotoStmt` is an unconditional jump.
*   **Example**:
    ```jimple
    if temp$0 == 0 goto label1;
    goto label2;
    ```

---

## 🎯 Application in `sootup-vulnfinder`
1.  **Secret Scan**: We will iterate through `JAssignStmt` instances. If the right-hand side is a constant string (`Constant`), we inspect it using regular expressions to detect AWS keys, API tokens, or credentials.
2.  **Taint Analysis (SQL Injection)**:
    *   **Source**: A `JIdentityStmt` loading a parameter (e.g. `username := @parameter0`) represents the entry point of untrusted user input.
    *   **Propagation**: When a `JAssignStmt` uses a tainted local in its right-hand side expression (like string concatenation), the target local variable becomes tainted.
    *   **Sink**: We look for a `JInvokeStmt` (or `JAssignStmt` invoking a method) where a tainted variable is passed to a database execution signature (e.g., `Statement.execute(...)`).
