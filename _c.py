import os
for f in ["_cleanup2.py", "bench_jq.py"]:
    if os.path.exists(f):
        os.remove(f)
print("done")
