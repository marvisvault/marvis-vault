#!/usr/bin/env python3
"""Generate a large JSON file to test size limits"""

import json

# Create 11MB of data (exceeds 10MB limit)
large_data = {
    "role": "user",
    "trustScore": 50,
    "data": "A" * (11 * 1024 * 1024)  # 11MB of 'A's
}

with open("test_large.json", "w") as f:
    json.dump(large_data, f)