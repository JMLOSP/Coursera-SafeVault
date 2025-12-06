SafeVault – Activity 3: Debugging & Security Hardening
Microsoft / Coursera – Secure Coding & Authentication Project
##  Introduction

During Activity 3, I analyzed, debugged, and strengthened the SafeVault application to eliminate remaining security vulnerabilities. Even though secure coding practices were previously applied, further testing revealed exposure to:

SQL injection attempts

Cross-Site Scripting (XSS) payloads

Unsafe handling of user-generated data

This report summarizes the vulnerabilities identified, the fixes applied with Copilot assistance, and the regression tests added to confirm SafeVault’s security posture.

##  1. Vulnerability Identification
### 1.1 SQL Injection Risks

Initial review showed that certain database operations could have used insecure string concatenation, e.g.:

"SELECT * FROM Users WHERE Username = '" + username + "'";


This opens the door to SQL injection attacks like:

juan'; DROP TABLE Users;--

Key Risk Identified

User input inserted directly into SQL statements without parameterization.

### 1.2 XSS (Cross-Site Scripting) Risks

Before corrections, user input from form fields could contain malicious HTML/JS such as:

<script>alert("xss")</script>


If later displayed in a UI or log output, this could execute arbitrary JavaScript.

Key Risk Identified

User input was not sanitized before processing or storage.

## 2. Fixes Applied
### 2.1 SQL Injection Mitigation – Parameterized Queries

Using Copilot suggestions, all SQL operations were refactored to use fully parameterized queries through SQLite:

cmd.Parameters.AddWithValue("$username", username);
cmd.Parameters.AddWithValue("$email", email);


This eliminates SQL injection threats entirely by preventing user input from being executed as SQL.

### 2.2 XSS Mitigation – Input Sanitization

A strong sanitization layer (InputSanitizer) was implemented to eliminate XSS vectors:

value = Regex.Replace(value, "<.*?>", "");
value = Regex.Replace(value, @"alert\s*\([^)]*\)", "", RegexOptions.IgnoreCase);
value = value.Replace("'", "").Replace("\"", "").Replace(";", "");


This solution:

Removes all HTML tags

Removes script patterns (e.g., alert(...))

Removes characters commonly used in injection attacks

This ensures SafeVault safely handles user input before storing or processing it.

### 2.3 Secure Authentication and Authorization (From Activity 2)

Already implemented and confirmed secure:

Password hashing with BCrypt

JWT token generation with role claims

Route protection using [Authorize(Roles = "admin")]

These mechanisms were validated again during this activity.

##  3. Security Regression Tests

To verify security fixes and ensure long-term resilience, I added several new tests simulating real attack vectors.

✔️ Test 1: Aggressive SQL Injection
[Test]
public void Sanitizer_Should_Remove_SQLInjection_Patterns()
{
    var payload = "x'; DROP TABLE Users; UPDATE Users SET Role='admin';--";
    var sanitized = _sanitizer.Sanitize(payload);

    Assert.That(sanitized, Does.Not.Contain("'"));
    Assert.That(sanitized, Does.Not.Contain(";"));
    Assert.That(sanitized, Does.Contain("DROP TABLE")); // safe as text
}

✔️ Test 2: Advanced XSS Attempt
[Test]
public void Sanitizer_Should_Remove_Advanced_XSS()
{
    var payload = "<img src=x onerror='alert(1)'><script>alert(2)</script>juan";
    var sanitized = _sanitizer.Sanitize(payload);

    Assert.That(sanitized, Does.Not.Contain("<"));
    Assert.That(sanitized, Does.Not.Contain("script"));
    Assert.That(sanitized, Does.Not.Contain("alert"));
    Assert.That(sanitized, Does.Contain("juan"));
}

✔️ Test 3: Mixed SQLi + XSS Attack
[Test]
public void Sanitizer_Should_Handle_Mixed_Attack_Payload()
{
    var payload = "<script>mal()</script>john'; DROP TABLE Users;--";
    var sanitized = _sanitizer.Sanitize(payload);

    Assert.That(sanitized, Does.Not.Contain("<"));
    Assert.That(sanitized, Does.Not.Contain("'"));
    Assert.That(sanitized, Does.Not.Contain(";"));
    Assert.That(sanitized, Does.Contain("john"));
}

##  4. Results and Validation

After applying fixes:

All regression tests passed successfully

SQL injection attempts are neutralized

XSS payloads are fully sanitized

Authentication & role-based authorization remain secure

The form-based registration (Activity 2) properly hashes passwords and stores roles

SafeVault’s backend is now robust against common web attack patterns

##  5. Final Summary

Using secure coding principles and Copilot-assisted debugging, SafeVault was upgraded to a secure and production-ready state.

Vulnerabilities Found

SQL injection potential in database queries

XSS risks from unsanitized input

Fixes Applied

Parameterized queries for all DB interactions

Sanitization and filtering of user input

Strong hashing (BCrypt) for passwords

JWT authentication + RBAC for sensitive endpoints

Validation

Unit tests simulating SQLi & XSS attacks

Role claim tests verifying authorization

All tests passed successfully
