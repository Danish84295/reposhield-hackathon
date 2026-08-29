# RepoShield Vulnerability Demo

This directory is an intentionally vulnerable C++ project used to demonstrate
RepoShield's security analysis capabilities.

Expected findings:

- RS001: Unsafe C string function (`strcpy`)
- RS002: Command execution (`system`)

Do not use this code in production.
