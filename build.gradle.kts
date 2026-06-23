plugins {
    java
    application
}

group = "com.vulnfinder"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // Core SootUp components
    implementation("org.soot-oss:sootup.core:2.0.0")
    implementation("org.soot-oss:sootup.java.core:2.0.0")
    
    // Bytecode and Sourcecode Frontends
    implementation("org.soot-oss:sootup.java.bytecode.frontend:2.0.0")
    implementation("org.soot-oss:sootup.java.sourcecode.frontend:2.0.0")
    
    // Analyses (e.g. Call Graph construction, CHA)
    implementation("org.soot-oss:sootup.analysis.intraprocedural:2.0.0")
    implementation("org.soot-oss:sootup.analysis.interprocedural:2.0.0")
    implementation("org.soot-oss:sootup.callgraph:2.0.0")
    
    // Testing
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

application {
    mainClass.set("com.vulnfinder.VulnFinder")
}

tasks.test {
    useJUnitPlatform()
}
