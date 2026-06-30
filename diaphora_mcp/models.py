"""
Diaphora MCP — shared data models and constants.

Security keyword lists, pseudo-code patterns, and match-type filters
used across multiple core modules.
"""

# ---------------------------------------------------------------------------
# Security-relevant keywords for analyze_diff_results.
# ---------------------------------------------------------------------------
SECURITY_KEYWORDS = [
    # Crypto
    "crypt", "encrypt", "decrypt", "aes", "rsa", "sha", "md5", "hash",
    "hmac", "cipher", "chacha", "salsa", "blake", "elliptic", "ecdh",
    "ecdsa", "hkdf", "pbkdf", "bcrypt", "scrypt", "argon2",
    # Auth / credentials
    "password", "passwd", "pwd", "credential", "auth", "oauth", "token",
    "session", "login", "permission", "privilege", "acl", "capability",
    "certificate", "cert", "x509", "tls", "ssl", "asn1",
    # Memory safety
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
    "strncat", "sprintf", "vsprintf", "snprintf", "vsnprintf", "scanf",
    "sscanf", "fscanf", "gets", "read", "recv", "malloc", "free",
    "realloc", "calloc", "alloc", "dealloc",
    # Input validation
    "validate", "sanitize", "escape", "check", "verify", "bounds",
    "overflow", "underflow", "integer_overflow", "off_by_one",
    "null_terminat", "format_string",
    # Process / memory
    "exec", "system", "shell", "fork", "spawn", "create_process",
    "load_library", "dlopen", "dlsym", "virtual_alloc", "virtual_protect",
    "write_process", "read_process", "code_inject",
    # File operations
    "fopen", "fwrite", "fread", "create_file", "write_file",
    "delete_file", "temp", "tmp", "path_traversal", "directory",
    # Networking
    "socket", "connect", "bind", "listen", "accept", "send", "recvfrom",
    "dns", "resolve", "url", "uri", "http", "https", "websocket",
]

# Common heuristic indicators that a change in a patch diff is security-relevant.
SECURITY_PSEUDO_PATTERNS = [
    "if (", ">= ", "<= ", "> ", "< ", "== 0", "!= 0",  # bounds checks
    "goto", "return -1", "return 0", "return false",
    "__except", "__try", "try {", "catch ", "throw",
    "null", "NULL", "nullptr",  # null checks
    "sizeof",  # buffer size tracking
]

# Mapping: keyword → categories for analyze_diff_results.
SECURITY_KEYWORD_CATEGORIES: dict = {
    "memory": {"memcpy", "memmove", "memset", "strcpy", "strncpy",
               "strcat", "strncat", "sprintf", "vsprintf", "snprintf",
               "vsnprintf", "scanf", "sscanf", "fscanf", "gets",
               "malloc", "free", "realloc", "calloc", "alloc", "dealloc"},
    "crypto": {"crypt", "encrypt", "decrypt", "aes", "rsa", "sha",
               "md5", "hash", "hmac", "cipher", "chacha", "blake",
               "elliptic", "ecdh", "ecdsa", "hkdf", "pbkdf",
               "bcrypt", "scrypt", "argon2"},
    "auth": {"password", "passwd", "pwd", "credential", "auth", "oauth",
             "token", "session", "login", "permission", "privilege",
             "acl", "capability"},
    "process": {"exec", "system", "shell", "fork", "spawn",
                "create_process", "load_library", "dlopen", "dlsym"},
    "network": {"socket", "connect", "bind", "listen", "accept",
                "send", "recvfrom", "dns", "url", "uri", "http", "https"},
    "validation": {"validate", "sanitize", "escape", "check", "verify",
                   "bounds", "overflow", "underflow"},
    "file_io": {"fopen", "fwrite", "fread", "create_file",
                "write_file", "delete_file", "temp", "tmp"},
    "memory_manipulation": {"virtual_alloc", "virtual_protect",
                             "write_process", "read_process", "code_inject"},
}

# ---------------------------------------------------------------------------
# Diaphora match-type filter
# ---------------------------------------------------------------------------
MATCH_TYPES = {
    "best": ("best",),
    "partial": ("partial",),
    "unreliable": ("unreliable",),
    "multimatch": ("multimatch",),
    "all": ("best", "partial", "unreliable", "multimatch"),
}
