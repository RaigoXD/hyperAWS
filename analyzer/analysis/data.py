"""Static reference data used by rules. Review periodically: these age.

Last reviewed: 2026-06. Runtime deprecations and previous-generation lists are
best-effort; always confirm against the AWS documentation before acting.
"""

# Lambda runtimes AWS has deprecated (no more security patches / updates).
DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "nodejs16.x", "nodejs18.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6",
    "go1.x", "java8", "ruby2.5", "ruby2.7", "provided",
}
# Runtimes that can run on arm64 (Graviton) Lambda.
LAMBDA_ARM_OK_PREFIXES = ("python3.", "nodejs", "java", "dotnet", "ruby", "provided.al")

# EC2 families that have a clearly better current generation.
PREVIOUS_GEN_EC2 = {"t2", "m3", "m4", "c3", "c4", "r3", "r4", "i2", "d2", "m1", "m2", "c1"}
PREVIOUS_GEN_RDS = {"db.t2", "db.m3", "db.m4", "db.r3", "db.r4"}

# Families with a Graviton (arm64) equivalent that is ~20% cheaper.
GRAVITON_CANDIDATE_FAMILIES = {"t3", "t3a", "m5", "m5a", "m6i", "m6a", "m7i", "m7a",
                               "c5", "c5a", "c6i", "c6a", "c7i", "c7a", "r5", "r5a", "r6i", "r6a", "r7i", "r7a"}

# Ports that should almost never be open to the internet.
SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached",
    2049: "NFS", 5984: "CouchDB", 9042: "Cassandra", 445: "SMB", 23: "Telnet", 21: "FTP",
}

# Environment synonyms -> canonical name.
ENV_ALIASES = {
    "prod": "prod", "production": "prod", "prd": "prod", "live": "prod",
    "stg": "staging", "stage": "staging", "staging": "staging", "preprod": "staging", "pre-prod": "staging",
    "dev": "dev", "development": "dev", "develop": "dev", "sandbox": "dev", "sbx": "dev",
    "test": "test", "testing": "test", "qa": "test", "uat": "test", "tst": "test",
}
