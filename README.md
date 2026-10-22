# eMudhra Intermediate CA Compromise
As-per [Wayne](https://emudhra.we-have-a-problem.com/) the private keys of eight eMudhra intermediate CAs were "compromised". They had trivially weak private keys, which could be brute-forced in milliseconds.

This repo contains scripts that demonstrate how an attacker may have been leveraging the "leaked" private keys to forge trusted certificates for malicious sites.

As of writing, the certs are revoked and therefore no longer trusted by up-to-date versions of the major browsers.

CLI tools like `curl`, `pip`, etc are obviously impacted as well, and should be updated.
