# Policy trust root

`policy-public.pem` is the Ed25519 public key that verifies ccshield policy bundles.

| Version | Created (TW) | Fingerprint (sha256 of SPKI DER) |
| --- | --- | --- |
| v1 | 2026-10-27 | `e93fc453b5591e9e83f05217d4c27cc665045d7f80992106b28e7039fb48d1a3` |

Check a key with:

```bash
node -e 'const c=require("crypto"),f=require("fs");console.log(c.createHash("sha256").update(c.createPublicKey(f.readFileSync(process.argv[1])).export({type:"spki",format:"der"})).digest("hex"))' policy/policy-public.pem
```
