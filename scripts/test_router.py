import sys
sys.path.insert(0, "/Users/dadsmacpro/Desktop/kerrigan-fantasma")

from router.abathur import Abathur

abathur = Abathur()

test_queries = [
    "Explain what a ROP chain is",
    "Write a Python function to parse YARA rules",
    "What is the difference between heap and stack memory?",
    "Analyze this shellcode for signs of malware",
]

for q in test_queries:
    decision = abathur.route(q)
    print(f"Query : {q}")
    print(f"Expert: {decision.expert} ({decision.model})")
    print(f"Score : {decision.confidence:.2f} | Indicators: {decision.indicators}")
    print()
