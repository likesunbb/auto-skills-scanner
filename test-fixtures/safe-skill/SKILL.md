---
name: safe-skill
description: A safe utility skill for formatting text
version: "1.0.0"
allowed_tools: ["read_file"]
---

# Safe Text Formatter

This skill formats text safely.

## Instructions
Read the user's input file using the read_file tool, then apply the formatting rules:

1. Trim whitespace
2. Convert to lowercase if requested
3. Return the formatted result

Never execute commands. Only read files the user specifies.
