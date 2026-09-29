# Shared Auth UI smoke apps

Three tiny clients exercise the same public contract:

- `ts/`: browser UI in TypeScript.
- `rust/`: browser UI in Rust/Yew compiled to WebAssembly.
- `flutter/`: Flutter UI for desktop/web/mobile builds.

Each app exposes email/password fields plus **Sign up** and **Log in** buttons.
The default backend is `http://127.0.0.1:8120`.

Expected endpoints:

- `POST /auth/register` with `{"email","password"}`
- `POST /auth/login` with `{"email","password"}`

Run the backend from `shared-auth/shared-auth-infra` with:

```sh
ores-compose up ./.ores-compose.yaml
```
