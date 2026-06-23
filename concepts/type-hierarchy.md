# Concept: Type Hierarchy & Metadata

## 📖 Definition
The **Type Hierarchy** represents the subclassing, interface implementation, and subtyping relationships between all classes in a program. 

**Metadata** refers to the structural definitions of classes (e.g. methods, fields, modifier flags, modifiers like `public`/`private`) loaded by the static analysis framework.

---

## 💡 Why It Matters in Static Analysis
To write robust security checks, we must be able to reason about types abstractly rather than matching exact class names.

### The Database Driver Sink Problem
Suppose we want to find SQL injections. We know query execution occurs on a database sink:
```java
java.sql.Statement.execute(String sql)
```
At runtime, the actual class instantiated might be a database-driver-specific implementation:
*   `com.mysql.cj.jdbc.StatementImpl` (MySQL)
*   `org.postgresql.jdbc.PgStatement` (Postgres)
*   `org.sqlite.jdbc4.JDBC4Statement` (SQLite)

Hardcoding all possible database driver classes is impossible. Instead, we check the **Type Hierarchy** to verify if the receiver object implements the standard `java.sql.Statement` interface.

---

## 🛠️ SootUp Type & Metadata API
SootUp 2.0.0 represents these concepts using the following classes:

### 1. Identifying Elements
Unlike the old Soot, which loaded classes into a global singleton, SootUp uses immutable signature descriptors built via an `IdentifierFactory`:
*   **`ClassType`**: Mapped from class names (e.g., `java.lang.String`).
*   **`MethodSignature`**: Mapped from the parent class type, method name, return type, and argument types list.
*   **`FieldSignature`**: Mapped from the parent class type, field name, and field type.

### 2. Loading Structural Class Definitions
A `JavaView` is queried using class types to retrieve a `JavaSootClass`:
```java
// Query class definition from the view
Optional<JavaSootClass> sootClassOpt = view.getClass(classType);

if (sootClassOpt.isPresent()) {
    JavaSootClass sootClass = sootClassOpt.get();
    
    // Query fields & methods
    List<JavaSootMethod> methods = sootClass.getMethods();
    List<JavaSootField> fields = sootClass.getFields();
    
    // Check flags
    boolean isAbstract = sootClass.isAbstract();
    boolean isInterface = sootClass.isInterface();
}
```

### 3. Subtype & Hierarchy Resolution
To check subclassing and subtype relationships, we query the `View` type hierarchy helper:
```java
// Retrieve type hierarchy resolver
TypeHierarchy hierarchy = view.getTypeHierarchy();

ClassType subClass = factory.getClassType("com.example.MySQLConnection");
ClassType superInterface = factory.getClassType("java.sql.Connection");

// Check if subClass implements/extends superInterface
if (hierarchy.isSubtypeOf(subClass, superInterface)) {
    System.out.println("Valid database connection subclass detected.");
}
```

---

## 🎯 Application in `sootup-vulnfinder`
1.  **Vulnerability Sink Detection**: When analyzing a `JInvokeStmt` (e.g. calling `stmt.execute(query)`), we retrieve the receiver local's class type. We use the `TypeHierarchy` from `JavaView` to check if that class type implements `java.sql.Statement` or `java.sql.PreparedStatement`.
2.  **Source Identification**: Check if a class structure extends popular web framework request handlers (like `javax.servlet.http.HttpServlet`) to auto-detect parameters as untrusted entry points.
