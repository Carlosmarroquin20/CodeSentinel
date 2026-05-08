// Sample vulnerable authentication module — used only for testing and demonstration.
// This file intentionally contains patterns that CodeSentinel is designed to detect.

const config = {
    // CS005: hardcoded API key
    apiKey: "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234",
    // CS005: hardcoded secret
    secret: "my-super-secret-token-value-xyz",
};

// CS004: hardcoded JWT (structure is valid but payload is synthetic)
const devToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0" +
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

function authenticate(username, password) {
    // Placeholder — do not ship this pattern
    return username === "admin" && password === config.secret;
}

module.exports = { authenticate };
