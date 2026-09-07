import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.Label;
import java.awt.Panel;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp Suite extension for AES-CBC encryption/decryption directly from the
 * context menu. No key or IV is bundled — each user configures their own via
 * "Set key/IV..." and it persists in the Burp project file.
 */
public class Extension implements BurpExtension {
    private static final String VERSION = "v1.0";
    private static final String PREF_KEY = "aes-crypto-key";
    private static final String PREF_IV = "aes-crypto-iv";
    private static final Pattern BASE64_TOKEN = Pattern.compile("[A-Za-z0-9+/]{20,}={0,2}");

    private static volatile MontoyaApi API;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        API = montoyaApi;
        montoyaApi.extension().setName("AES Crypto Tools");
        montoyaApi.userInterface().registerContextMenuItemsProvider(new CryptoMenu());
        montoyaApi.logging().logToOutput("AES Crypto Tools " + VERSION + " loaded - set your key/IV via the context menu");
    }

    private static final class CryptoMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
            boolean hasSelection = editor.isPresent() && editor.get().selectionOffsets().isPresent();

            JMenu crypto = new JMenu("AES Crypto");

            JMenuItem config = new JMenuItem("Set key/IV...");
            config.addActionListener(e -> showConfigDialog());
            crypto.add(config);

            if (hasSelection) {
                JMenuItem decrypt = new JMenuItem("Decrypt selected text");
                JMenuItem encrypt = new JMenuItem("Encrypt selected text");
                decrypt.addActionListener(e -> transform(editor.get(), false));
                encrypt.addActionListener(e -> transform(editor.get(), true));
                crypto.add(decrypt);
                crypto.add(encrypt);
            }
            return List.of(crypto);
        }

        private void showConfigDialog() {
            Preferences prefs = API.persistence().preferences();
            String savedKey = prefs.getString(PREF_KEY);
            String savedIv = prefs.getString(PREF_IV);
            JTextField keyField = new JTextField(savedKey != null ? savedKey : "", 40);
            JTextField ivField = new JTextField(savedIv != null ? savedIv : "", 40);

            Panel panel = new Panel(new GridLayout(2, 2, 5, 5));
            panel.add(new Label("Key (16/24/32 chars):"));
            panel.add(keyField);
            panel.add(new Label("IV (16 chars):"));
            panel.add(ivField);

            int result = JOptionPane.showConfirmDialog(null, panel, "AES Crypto - Configuration",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (result != JOptionPane.OK_OPTION) {
                return;
            }

            String key = keyField.getText();
            String iv = ivField.getText();
            if (!List.of(16, 24, 32).contains(key.getBytes(StandardCharsets.UTF_8).length)) {
                JOptionPane.showMessageDialog(null, "Key must be 16, 24 or 32 bytes (currently "
                        + key.getBytes(StandardCharsets.UTF_8).length + ").", "AES Crypto", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (iv.getBytes(StandardCharsets.UTF_8).length != 16) {
                JOptionPane.showMessageDialog(null, "IV must be exactly 16 bytes (currently "
                        + iv.getBytes(StandardCharsets.UTF_8).length + ").", "AES Crypto", JOptionPane.ERROR_MESSAGE);
                return;
            }

            prefs.setString(PREF_KEY, key);
            prefs.setString(PREF_IV, iv);
            API.logging().logToOutput("Key/IV updated and saved to Burp project.");
            JOptionPane.showMessageDialog(null, "Key/IV saved. It persists across Burp restarts.", "AES Crypto",
                    JOptionPane.INFORMATION_MESSAGE);
        }

        private void transform(MessageEditorHttpRequestResponse editor, boolean encrypt) {
            try {
                if (keyBytes() == null || ivBytes() == null) {
                    JOptionPane.showMessageDialog(null,
                            "No key/IV configured yet.\n\nClick OK to configure them now.",
                            "AES Crypto", JOptionPane.WARNING_MESSAGE);
                    showConfigDialog();
                    return;
                }
                doTransform(editor, encrypt);
            } catch (Exception ex) {
                if (API != null) {
                    API.logging().logToError("AES Crypto transform failed", ex);
                }
                JOptionPane.showMessageDialog(null,
                        "Unexpected error (" + (encrypt ? "encrypt" : "decrypt") + "):\n\n" + ex,
                        "AES Crypto", JOptionPane.ERROR_MESSAGE);
            }
        }

        private void doTransform(MessageEditorHttpRequestResponse editor, boolean encrypt) {
            Range range = editor.selectionOffsets().orElseThrow();
            boolean request = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;

            String message = request
                    ? editor.requestResponse().request().toString()
                    : editor.requestResponse().response().toString();
            if (range.startIndexInclusive() >= range.endIndexExclusive()
                    || range.endIndexExclusive() > message.length()) {
                JOptionPane.showMessageDialog(null, "Invalid selection range.", "AES Crypto", JOptionPane.WARNING_MESSAGE);
                return;
            }

            String selected = message.substring(range.startIndexInclusive(), range.endIndexExclusive());
            String replacement;
            try {
                replacement = encrypt ? encrypt(selected) : decrypt(selected);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null,
                        "Failed (" + (encrypt ? "encrypt" : "decrypt") + "):\n\n" + ex,
                        "AES Crypto", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!encrypt) {
                JOptionPane.showMessageDialog(null,
                        replacement.length() > 4000 ? replacement.substring(0, 4000) + "\n..." : replacement,
                        "AES Crypto - Decrypted", JOptionPane.INFORMATION_MESSAGE);
            }

            // Response editors in Repeater are read-only, so replacing text there
            // may fail — the popup above already carries the result.
            try {
                String updated = message.substring(0, range.startIndexInclusive())
                        + replacement
                        + message.substring(range.endIndexExclusive());
                if (request) {
                    editor.setRequest(HttpRequest.httpRequest(updated));
                } else {
                    editor.setResponse(HttpResponse.httpResponse(updated));
                }
            } catch (Exception readOnly) {
                if (API != null) {
                    API.logging().logToOutput("Editor is read-only, result shown in popup only.");
                }
            }
        }
    }

    // Returns null when the user has not configured a key/IV yet.
    private static byte[] keyBytes() {
        String key = API.persistence().preferences().getString(PREF_KEY);
        return key != null ? key.getBytes(StandardCharsets.UTF_8) : null;
    }

    // Returns null when the user has not configured an IV yet.
    private static byte[] ivBytes() {
        String iv = API.persistence().preferences().getString(PREF_IV);
        return iv != null ? iv.getBytes(StandardCharsets.UTF_8) : null;
    }

    // AES/CBC/PKCS5Padding, Base64 — the common CryptoJS frontend pattern.
    private static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes(), "AES"), new IvParameterSpec(ivBytes()));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    private static String decrypt(String selection) throws Exception {
        String ciphertext = extractBase64(selection);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes(), "AES"), new IvParameterSpec(ivBytes()));
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
    }

    // Tolerates selections that include surrounding JSON/quotes/whitespace,
    // e.g. {"data":"<base64>"} — falls back to the longest base64-looking token.
    private static String extractBase64(String selection) throws Exception {
        String trimmed = selection.trim();
        try {
            Base64.getDecoder().decode(trimmed);
            return trimmed;
        } catch (IllegalArgumentException directDecodeFailed) {
            Matcher m = BASE64_TOKEN.matcher(selection);
            String best = null;
            while (m.find()) {
                String token = m.group();
                if (best == null || token.length() > best.length()) {
                    best = token;
                }
            }
            if (best == null) {
                throw new IllegalArgumentException("No base64 ciphertext found in selection.");
            }
            return best;
        }
    }
}
