package com.aigitassist.service;

import com.aigitassist.model.ValidationResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class SecurityValidationService {

    /**
     * Validates git diff for sensitive information using industry-standard patterns.
     * @param diff The git diff content to validate
     * @return ValidationResult indicating if diff is safe and list of violations
     */
    public ValidationResult validateDiff(String diff) {
        if (diff == null || diff.trim().isEmpty()) {
            return new ValidationResult(true, Collections.emptyList());
        }

        List<String> violations = new ArrayList<>();
        
        // Check for AWS Access Keys
        if (Pattern.compile("AKIA[0-9A-Z]{16}").matcher(diff).find()) {
            violations.add("AWS Access Key detected");
        }
        
        // Check for GitHub Personal Access Tokens
        if (Pattern.compile("ghp_[a-zA-Z0-9]{36}").matcher(diff).find()) {
            violations.add("GitHub Personal Access Token detected");
        }
        
        // Check for Private Keys
        if (Pattern.compile("-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----").matcher(diff).find()) {
            violations.add("Private key detected");
        }
        
        // Check for API keys, passwords, and secrets
        if (Pattern.compile("(?i)(api[_-]?key|password|secret|token)\\s*[=:]\\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?").matcher(diff).find()) {
            violations.add("API key, password, or secret detected");
        }
        
        // Check for .env files
        if (Pattern.compile("(?i)[/\\\\]\\.env").matcher(diff).find()) {
            violations.add(".env file detected");
        }

        return new ValidationResult(violations.isEmpty(), violations);
    }

}

