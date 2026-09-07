# AES Crypto Tools — Burp Suite Extension

A lightweight Burp Suite extension (Montoya API) for encrypting and decrypting
AES-CBC text directly from the right-click context menu.

Useful when testing web applications whose frontend encrypts request/response
bodies with a static AES key (the common CryptoJS `AES.encrypt()` pattern found
in JavaScript bundles).

**No key or IV is bundled with this extension.** You supply your own via the
in-extension configuration dialog; it is stored in your Burp project file and
persists across restarts.

## Features

- **Decrypt selected text** — select any ciphertext (raw Base64, or JSON that
  contains it such as `{"data":"<base64>"}`) in a request/response editor and
  decrypt it in place / via popup.
- **Encrypt selected text** — encrypt selected plaintext back to Base64
  ciphertext (works in editable request panes).
- **Set key/IV...** — configure your AES key and IV at runtime. No rebuild
  needed. Saved to Burp's project persistence.
- Errors are always surfaced in a dialog (never silent failures).

## Cryptography

| Setting | Value |
|---|---|
| Algorithm | AES |
| Mode | CBC |
| Padding | PKCS5Padding (PKCS7-compatible) |
| Key encoding | UTF-8, 16 / 24 / 32 bytes (AES-128/192/256) |
| IV encoding | UTF-8, exactly 16 bytes |
| Ciphertext encoding | Base64 |

This matches the output of the typical frontend code:

```js
CryptoJS.AES.encrypt(text, CryptoJS.enc.Utf8.parse(key),
    { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7, iv: CryptoJS.enc.Utf8.parse(iv) }).toString()
```

Not supported: AES/GCM, AES/ECB, dynamic per-session keys, hex-encoded keys.

## Installation

1. Download the JAR from `release/` (or build it yourself, see below).
2. In Burp Suite: **Extensions → Installed → Add**.
3. Extension type: **Java**, select the JAR file.
4. The extension output should show:
   `AES Crypto Tools v1.0 loaded - set your key/IV via the context menu`

## Usage

1. **Configure once:** right-click anywhere in a message editor →
   **Extensions → AES Crypto → Set key/IV...** — enter the key and IV you
   found in the target application, click OK. They are saved to the Burp
   project and survive restarts.
2. **Decrypt:** open a request/response in Repeater (or Proxy message editor),
   select the ciphertext, right-click →
   **Extensions → AES Crypto → Decrypt selected text**.
   - The plaintext is shown in a popup.
   - In editable panes (e.g. the Repeater request tab) the selected text is
     also replaced in place.
   - Read-only panes (e.g. Repeater response tab) show the result in the
     popup only — Burp does not allow editing those.
3. **Encrypt:** select plaintext in an editable request pane →
   **Extensions → AES Crypto → Encrypt selected text**.

Tip: you don't need to select the Base64 precisely — selecting the whole JSON
body works too; the extension extracts the longest Base64-looking token.

## Building

Requirements: JDK 21.

```bash
./gradlew jar
```

The JAR is produced in `build/libs/`.

Alternatively, with just `javac` and the Montoya API JAR:

```bash
javac -cp montoya-api-2026.7.jar -d out src/main/java/Extension.java
jar cfe build/libs/extension-template-project.jar Extension -C out .
```

## How it works

- Registers a `ContextMenuItemsProvider` (Montoya API) that adds the
  **AES Crypto** menu to Burp message editors.
- On decrypt/encrypt it reads the current selection offsets from the message
  editor, extracts the ciphertext, runs `AES/CBC/PKCS5Padding` via
  `javax.crypto.Cipher`, and writes the result back (or shows it in a dialog).
- The key/IV live in Burp's project-level `Preferences`
  (`aes-crypto-key`, `aes-crypto-iv`) — never inside the JAR.

## Legal / responsible use

This extension is intended for **authorized security testing** (pentest
engagements, bug bounty, security research on systems you have permission to
test). You are responsible for obtaining the target's key/IV material through
 lawful means and for complying with applicable laws.

## License

MIT
