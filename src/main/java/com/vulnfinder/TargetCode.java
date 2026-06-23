package com.vulnfinder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class TargetCode {

    // Vulnerability 1: Hardcoded credentials / secret key
    private static String AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static String SLACK_TOKEN = "xoxb-123456789012-1234567890123-456789abcdef";

    public void processUserData(String username, String password) {
        try {
            // Vulnerability 2: SQL Injection via unsanitized input concatenation
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", username, password);
            Statement stmt = conn.createStatement();
            
            // Source: 'username' parameter
            // Sink: 'stmt.execute'
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            stmt.execute(query);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        TargetCode target = new TargetCode();
        target.processUserData("admin' OR '1'='1", "password123");
    }
}
