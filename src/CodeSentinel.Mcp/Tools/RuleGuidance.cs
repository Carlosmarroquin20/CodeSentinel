namespace CodeSentinel.Mcp.Tools;

internal sealed record RuleGuidance(
    string Detects,
    string Risk,
    IReadOnlyList<string> Remediation);

// Long-form explanations for explain_rule. RuleMetadata carries a one-line description
// that also goes into reports; this text is written for an agent deciding how to fix a
// finding. A test fails when a registered rule has no entry here.
internal static class RuleGuidanceCatalog
{
    private const string RotateBeforeCleaning =
        "Removing the value in a new commit does not remove it from Git history, clones or forks. "
        + "Revoke or rotate it first; rewriting history afterwards is optional clean-up.";

    private static readonly Dictionary<string, RuleGuidance> Entries = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CS001"] = new(
            Detects: "Strings of AKIA or ASIA followed by 16 upper-case letters or digits: the identifier half "
                + "of an AWS access key pair. AKIA marks a long-term IAM user key, ASIA temporary STS credentials.",
            Risk: "Together with its secret key it lets anyone call AWS APIs with the permissions of that IAM "
                + "identity, for example to read S3 data or start resources billed to the account. The two halves "
                + "are usually stored together, so a committed key ID often means the secret is nearby.",
            Remediation:
            [
                "Deactivate and delete the access key in IAM, then create a new one only if it is still needed.",
                "Review CloudTrail for activity by that key since it was committed.",
                "Load credentials from environment variables, the AWS shared credentials file, an IAM role or "
                    + "IAM Identity Center instead of source code.",
                RotateBeforeCleaning,
            ]),

        ["CS002"] = new(
            Detects: "A 40-character value made of letters, digits, '/', '+' or '=' assigned to a name such as "
                + "aws_secret_access_key or aws_secret.",
            Risk: "The secret access key signs every AWS API request. With the matching key ID it grants full use "
                + "of the IAM identity's permissions until the key is deactivated.",
            Remediation:
            [
                "Deactivate and delete the key pair in IAM and issue a new one if it is still needed.",
                "Review CloudTrail for activity by the key since it was committed.",
                "Read credentials from the environment, the AWS shared credentials file or an IAM role at runtime.",
                RotateBeforeCleaning,
            ]),

        ["CS003"] = new(
            Detects: "PEM header lines that start a private key: RSA, EC, DSA, OpenSSH, PKCS#8 (including encrypted "
                + "keys) and ASCII-armored OpenPGP private key blocks.",
            Risk: "Whoever has the key can act as its owner: log in over SSH where the public key is authorized, "
                + "impersonate a TLS server, or sign commits, packages and messages. An encrypted key is still "
                + "exposed to offline passphrase guessing.",
            Remediation:
            [
                "Treat the key as compromised: revoke its certificate, remove the public key from authorized_keys, "
                    + "deploy keys and key servers, and generate a new key pair.",
                "Keep private keys outside the repository, in a secrets manager, key vault or CI secret, and add "
                    + "their file names to .gitignore.",
                "For test fixtures, generate a throwaway key during test setup instead of committing one.",
                RotateBeforeCleaning,
            ]),

        ["CS004"] = new(
            Detects: "Three base64url segments separated by dots where the first two begin with eyJ (the encoding "
                + "of '{\"'): the shape of a JSON Web Token.",
            Risk: "A JWT is a bearer credential: whoever holds it is treated as its subject until it expires, and "
                + "service tokens committed to code often have long or no expiry. The payload is only encoded, so "
                + "it can also reveal user IDs, e-mail addresses or internal claims.",
            Remediation:
            [
                "If the token is or was valid, revoke it. Where tokens cannot be revoked one by one, rotate the "
                    + "signing key so every token it issued becomes invalid.",
                "Obtain tokens at runtime from the identity provider or from configuration that is not committed.",
                "In tests, mint tokens during setup with a test-only signing key.",
            ]),

        ["CS005"] = new(
            Detects: "A quoted value of 8 or more characters assigned with '=' or ':' to a name such as password, "
                + "passwd, pwd, secret, api_key, apikey, token, access_key or client_secret.",
            Risk: "Anyone with read access to the repository can read the credential, and it travels with every "
                + "clone, fork, build artifact and backup. Changing it requires a code change, so it tends to stay "
                + "valid for a long time.",
            Remediation:
            [
                "Change the password or key on the system it belongs to.",
                "Read the value at runtime from environment variables, a secrets manager (AWS Secrets Manager, "
                    + "Azure Key Vault, HashiCorp Vault, ...) or development-only user secrets.",
                "Leave the value empty in committed configuration files and document where it comes from.",
                RotateBeforeCleaning,
            ]),

        ["CS006"] = new(
            Detects: "GitHub tokens: ghp_ (classic personal access token), gho_ (OAuth), ghu_ (user-to-server), "
                + "ghs_ (server-to-server, such as app installations) and ghr_ (refresh) followed by 36 characters, "
                + "and fine-grained personal access tokens starting with github_pat_.",
            Risk: "Depending on its scopes, the token can read private repositories, push code, change repository "
                + "or organization settings, and reach packages or Actions secrets as its owner.",
            Remediation:
            [
                "Revoke the token in GitHub (Settings > Developer settings for personal tokens, or the OAuth or "
                    + "GitHub App that issued it) and review the security log for its use.",
                "In GitHub Actions use the built-in GITHUB_TOKEN or a repository secret; locally use "
                    + "'gh auth login' or a Git credential helper.",
                "Prefer fine-grained tokens limited to specific repositories, with an expiry date.",
                RotateBeforeCleaning,
            ]),

        ["CS007"] = new(
            Detects: "Slack tokens with the prefixes xoxb- (bot), xoxp- (user), xoxa-, xoxo-, xoxs-, xoxr- and "
                + "xapp- (app-level).",
            Risk: "The token can read channels and direct messages, post as the bot or user, and export workspace "
                + "data, depending on the scopes granted to the app.",
            Remediation:
            [
                "Revoke the token or regenerate it from the app's settings at api.slack.com, and check the "
                    + "workspace access logs.",
                "Store the token in a secrets manager or environment variable read by the app at runtime.",
                "Request only the OAuth scopes the integration needs.",
                RotateBeforeCleaning,
            ]),

        ["CS008"] = new(
            Detects: "Stripe secret keys (sk_live_, sk_test_) and restricted keys (rk_live_, rk_test_) followed by "
                + "at least 24 letters or digits.",
            Risk: "A live secret key can create charges and refunds, read customer and payment data, and change "
                + "payout settings. Test keys expose test-mode data and show where live keys are likely kept.",
            Remediation:
            [
                "Roll the key in the Stripe Dashboard (Developers > API keys) and review recent API requests.",
                "Keep secret keys on the server, read from a secrets manager or environment variable. Client code "
                    + "should only ever see the publishable key (pk_).",
                "Use restricted keys with the minimum permissions each service needs.",
                RotateBeforeCleaning,
            ]),

        ["CS009"] = new(
            Detects: "Google API keys: AIza followed by 35 letters, digits, '-' or '_'.",
            Risk: "Calls made with the key are billed to the Google Cloud project and count against its quotas. "
                + "An unrestricted key can call every API enabled in the project. Some keys, such as those for "
                + "Maps JavaScript or Firebase, are meant to ship in client code; for those, restrictions are what "
                + "protect them.",
            Remediation:
            [
                "If the key is not meant to be public, delete or regenerate it in Google Cloud console > "
                    + "APIs & Services > Credentials.",
                "Add API restrictions and application restrictions (HTTP referrers, IP addresses, Android or iOS "
                    + "apps) to every key.",
                "Keep server-side keys in a secrets manager or environment variable.",
            ]),

        ["CS010"] = new(
            Detects: "npm access tokens: npm_ followed by 36 letters or digits.",
            Risk: "A token with publish rights lets an attacker release malicious versions of every package the "
                + "account maintains, a supply-chain attack on all of their users. Read tokens expose private "
                + "packages.",
            Remediation:
            [
                "Revoke the token on npmjs.com (Access Tokens) and check the packages for versions you did not "
                    + "publish.",
                "Do not commit an .npmrc that contains the token. Reference an environment variable instead "
                    + "(//registry.npmjs.org/:_authToken=${NPM_TOKEN}) and set it from a CI secret.",
                "Use granular tokens limited to specific packages, with an expiry date, or trusted publishing "
                    + "from CI.",
                RotateBeforeCleaning,
            ]),

        ["CS101"] = new(
            // API names are written without call parentheses so this text does not match CS101 when
            // CodeSentinel scans its own source.
            Detects: "Use of MD5 or SHA-1: the MD5.Create and SHA1.Create factory methods and the "
                + "MD5CryptoServiceProvider constructor in .NET, hashlib.md5 and hashlib.sha1 calls in Python, and "
                + "MessageDigest.getInstance with \"MD5\", \"SHA-1\" or \"SHA1\" in Java.",
            Risk: "Both algorithms have practical collision attacks, so they cannot protect integrity or "
                + "signatures. They are also fast, so passwords hashed with them can be brute-forced at billions of "
                + "guesses per second.",
            Remediation:
            [
                "For integrity checks and signatures use SHA-256 or stronger (SHA256 in .NET, hashlib.sha256 in "
                    + "Python, \"SHA-256\" in Java).",
                "For passwords use a password hashing function such as Argon2id, scrypt, bcrypt, or PBKDF2 with a "
                    + "high iteration count (Rfc2898DeriveBytes.Pbkdf2 in .NET, hashlib.scrypt in Python).",
                "If the hash is not used for security (cache keys, ETags, checksums required by another system), "
                    + "keep it and add 'codesentinel:ignore CS101' with a comment explaining why.",
            ]),

        ["CS900"] = new(
            Detects: "Quoted strings of 20 or more characters that use only base64, base64url or hex characters, "
                + "contain both letters and digits, and have a Shannon entropy of at least 4.5 bits per character. "
                + "Subresource Integrity digests (sha512-...) are skipped. This is a heuristic with lower "
                + "confidence (0.6) than the pattern rules.",
            Risk: "Random-looking strings are often credentials from providers without a recognizable prefix: API "
                + "keys, tokens, signing secrets or generated passwords. The same rule also matches harmless "
                + "values such as content hashes, public identifiers or test data, so each finding needs a look.",
            Remediation:
            [
                "Open the file at the reported line and identify what the value is.",
                "If it is a credential, rotate it with its provider and load it at runtime from a secrets manager "
                    + "or environment variable.",
                "If it is not secret, add 'codesentinel:ignore CS900' on that line, or exclude generated files "
                    + "with a glob in .codesentinelignore.",
            ]),
    };

    public static IReadOnlyCollection<string> RuleIds => Entries.Keys;

    public static RuleGuidance? Find(string ruleId) =>
        Entries.GetValueOrDefault(ruleId);
}
