# Candidate object-store TLS material

This directory intentionally contains no certificate or private-key files in Git.

`deploy/install-site.sh` generates `ca.crt` / `public.crt` / `private.key` here when they are missing. That is internal MinIO TLS, not the platform card-encryption key set. The CA private key is written to `/opt/authorization-platform-object-store-ca.key`. Existing files are left untouched.

- `ca.crt` — trusted CA mounted into the application and `mc` init container;
- `public.crt` — MinIO server certificate;
- `private.key` — MinIO server private key, mode `0600`.

The CA private key stays outside the application checkout. The generated files
are runtime secrets/material and must be backed up and rotated through the
deployment secret procedure, never committed to the repository.
