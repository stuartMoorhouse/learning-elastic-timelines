"""Check that the synthetic OT telemetry only uses ECS fields, plus custom fields modelled the way the ECS
"Custom fields" guidance recommends (https://www.elastic.co/docs/reference/ecs/ecs-custom-fields-in-ecs):
  1. labels.*                         ECS's own key/value field for extra keyword data
  2. nested under a proper name       e.g. zeek.*, winlog.* (what the Filebeat modules and integrations do)
  3. a capitalised name               e.g. process.Ext.*; ECS never capitalises, so it cannot clash with future ECS fields

Usage: python3 scripts/ot_telemetry.py | python3 scripts/check_ot_ecs.py [path/to/ecs fields.csv]
Without an argument it downloads the ECS field list from github.com/elastic/ecs (public file).
"""
import collections
import csv
import io
import ipaddress
import json
import re
import sys
import urllib.request

ECS_FIELDS_URL = "https://raw.githubusercontent.com/elastic/ecs/main/generated/csv/fields.csv"

# Proper-name namespaces used by the real integrations (strategy 2).
PROPER_NAMES = ("zeek.", "winlog.")
# Strategy 3: any capitalised path segment, e.g. process.Ext.*
CAPITALISED = re.compile(r"(^|\.)[A-Z]")
MAC_RFC_7042 = re.compile(r"([0-9A-F]{2}-){5}[0-9A-F]{2}")

# Allowed values for the ECS fields that define a fixed set.
ALLOWED = {
    "event.kind": {"alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"},
    "event.category": {
        "api", "authentication", "configuration", "database", "driver", "email", "file", "host", "iam",
        "intrusion_detection", "library", "malware", "network", "package", "process", "registry", "session",
        "threat", "vulnerability", "web",
    },
    "event.type": {
        "access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied", "end", "error",
        "group", "indicator", "info", "installation", "protocol", "start", "user",
    },
    "event.outcome": {"failure", "success", "unknown"},
    "network.direction": {"ingress", "egress", "inbound", "outbound", "internal", "external", "unknown"},
}


def load_ecs_types():
    """Map every ECS field name to its type, from a local CSV or the public ECS file."""
    if len(sys.argv) > 1:
        source = open(sys.argv[1])
    else:
        source = io.StringIO(urllib.request.urlopen(ECS_FIELDS_URL).read().decode())
    return {row["Field"]: row["Type"] for row in csv.DictReader(source)}


def flat(obj, prefix=""):
    """Yield (dotted path, value) for every leaf of a nested document."""
    for key, value in obj.items():
        path = prefix + key
        if isinstance(value, dict):
            yield from flat(value, path + ".")
        else:
            yield path, value


def check_ecs_value(path, ecs_type, value, problems):
    """Record a problem if a value does not fit its ECS field."""
    if ecs_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            problems[path].add("not an ip: %r" % value)
    if ecs_type in ("long", "integer", "float") and not isinstance(value, (int, float)):
        problems[path].add("not numeric: %r" % value)
    if ecs_type == "keyword" and not isinstance(value, str):
        problems[path].add("not a string: %r" % value)
    if path in ALLOWED and value not in ALLOWED[path]:
        problems[path].add("value not allowed by ECS: %r" % value)
    if path == "source.mac" and not MAC_RFC_7042.fullmatch(value):
        problems[path].add("MAC not RFC 7042 format: %r" % value)


def custom_kind(path):
    """Name the ECS custom-field strategy a non-ECS path follows, or None if it follows none."""
    if path.startswith("labels."):
        return "labels"
    if path.startswith(PROPER_NAMES):
        return "proper name"
    if CAPITALISED.search(path):
        return "capitalised"
    return None


def main():
    ecs = load_ecs_types()
    problems = collections.defaultdict(set)
    seen = collections.Counter()
    custom = collections.Counter()
    documents = 0

    for line in sys.stdin:
        doc = json.loads(line)
        if "create" in doc:  # bulk action line, not a document
            continue
        documents += 1
        for path, value in flat(doc):
            seen[path] += 1
            if path in ecs:
                values = value if isinstance(value, list) else [value]
                for item in values:
                    check_ecs_value(path, ecs[path], item, problems)
                continue
            kind = custom_kind(path)
            if kind:
                custom["%s  [%s]" % (path, kind)] += 1
            else:
                problems[path].add("not an ECS field")

    print("documents checked:", documents)
    print("distinct field paths:", len(seen))
    print("ECS fields used  :", sum(1 for path in seen if path in ecs))
    print("custom fields (valid per the ECS custom-fields guidance):")
    for path in sorted(custom):
        print("   ", path)
    if problems:
        print("PROBLEMS:")
        for path in sorted(problems):
            print("   ", path, "->", "; ".join(sorted(problems[path]))[:150])
        sys.exit(1)
    print("RESULT: every field is ECS or a custom field modelled per the ECS guidance; ECS values valid")


if __name__ == "__main__":
    main()
