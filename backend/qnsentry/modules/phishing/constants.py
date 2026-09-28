"""Values shared by the phishing checks, so they are defined in one place."""

# Name of the module in findings and module runs (data contract 10.1)
MODULE = "phishing"

# Top-level domains to try for lookalikes: badsecurityinc.be -> badsecurityinc.com, .eu, ...
# The client's own TLD is skipped automatically.
ALTERNATIVE_TLDS = ("be", "com", "net", "org", "eu", "nl", "fr", "de", "io")
