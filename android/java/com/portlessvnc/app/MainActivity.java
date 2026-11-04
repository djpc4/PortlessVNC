// The app's only activity: Rust (libportlessvnc.so, via NativeActivity) draws
// everything; this class adds what NativeActivity lacks - the on-screen
// keyboard, the file picker / "Open with", clipboard, Downloads and full screen.
package com.portlessvnc.app;

import android.app.NativeActivity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.view.inputmethod.BaseInputConnection;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends NativeActivity {
    static {
        System.loadLibrary("portlessvnc");
    }

    // kind: 1 text, 2 key down, 3 key up, 4 file, 5 clipboard, 6 back, 7 keyboard hidden
    static native void nativeEvent(int kind, int code, String text, byte[] data);

    private static final int PICK_FILE = 1;
    private KeyInput input;
    private boolean keyboardShown;

    @Override
    protected void onCreate(Bundle state) {
        // Java-side crashes land in the same report the Rust side writes
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        final File report = new File(getFilesDir(), "crash.txt");
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try (java.io.PrintWriter w = new java.io.PrintWriter(report)) {
                w.println("PortlessVNC crashed (Java): " + e);
                e.printStackTrace(w);
            } catch (Exception ignored) {
            }
            if (prev != null) prev.uncaughtException(t, e);
        });
        super.onCreate(state);
        input = new KeyInput(this);
        addContentView(input, new ViewGroup.LayoutParams(1, 1));
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null) {
            readUri(intent.getData());
        }
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (!hasFocus) return;
        // Android only lets the focused app read the clipboard
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = cm.getPrimaryClip();
            if (clip != null && clip.getItemCount() > 0) {
                CharSequence t = clip.getItemAt(0).coerceToText(this);
                if (t != null && t.length() > 0) nativeEvent(5, 0, t.toString(), null);
            }
        } catch (Exception ignored) {
        }
    }

    private long lastBack;

    @Override
    public void onBackPressed() {
        // Android may report one press twice (key and back-navigation paths)
        long now = android.os.SystemClock.uptimeMillis();
        if (now - lastBack < 700) return;
        lastBack = now;
        nativeEvent(6, 0, null, null);
    }

    // ---- called from Rust -------------------------------------------------

    public void showKeyboard(final boolean show) {
        runOnUiThread(() -> {
            InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (show) {
                input.setFocusableInTouchMode(true);
                input.requestFocus();
                imm.restartInput(input);
                imm.showSoftInput(input, InputMethodManager.SHOW_FORCED);
                // the UI toolkit may hide it again right after: ask once more
                input.postDelayed(() -> {
                    if (keyboardShown && !imeVisible()) imm.showSoftInput(input, InputMethodManager.SHOW_FORCED);
                }, 350);
            } else {
                imm.hideSoftInputFromWindow(input.getWindowToken(), 0);
            }
            keyboardShown = show;
        });
    }

    private boolean imeVisible() {
        if (Build.VERSION.SDK_INT < 30) return true;
        WindowInsets w = getWindow().getDecorView().getRootWindowInsets();
        return w != null && w.isVisible(WindowInsets.Type.ime());
    }

    public void pickFile() {
        runOnUiThread(() -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            try {
                startActivityForResult(i, PICK_FILE);
            } catch (Exception e) {
                toast("No file picker available");
            }
        });
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == PICK_FILE && result == RESULT_OK && data != null && data.getData() != null) {
            readUri(data.getData());
        }
    }

    private void readUri(Uri uri) {
        String name = "profile.ovpn";
        try (Cursor c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) name = c.getString(0);
        } catch (Exception ignored) {
            String p = uri.getLastPathSegment();
            if (p != null) name = p;
        }
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > 4 * 1024 * 1024) throw new Exception("file too large");
            }
            nativeEvent(4, 0, name, out.toByteArray());
        } catch (Exception e) {
            toast("Could not read the file: " + e.getMessage());
        }
    }

    public void setClipboard(final String text) {
        runOnUiThread(() -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("PortlessVNC", text));
        });
    }

    public void showCrashReport(final String text) {
        runOnUiThread(() -> {
            android.widget.TextView tv = new android.widget.TextView(this);
            tv.setText(text);
            tv.setTextIsSelectable(true);
            tv.setTextSize(11);
            tv.setPadding(32, 24, 32, 24);
            android.widget.ScrollView sv = new android.widget.ScrollView(this);
            sv.addView(tv);
            new android.app.AlertDialog.Builder(this)
                .setTitle("PortlessVNC crashed last time")
                .setView(sv)
                .setCancelable(false)
                .setPositiveButton("Copy report", (d, w) -> {
                    setClipboard(text);
                    toast("Report copied - paste it to the developer");
                    restart();
                })
                .setNegativeButton("Try again", (d, w) -> restart())
                .show();
        });
    }

    private void restart() {
        runOnUiThread(() -> {
            finishAffinity();
            System.exit(0);
        });
    }

    /** Areas covered by the status/navigation bars, the camera cutout and the
     *  on-screen keyboard, in pixels: {top, bottom, left, right, keyboard}. */
    public int[] getInsets() {
        int[] r = new int[5];
        View decor = getWindow().getDecorView();
        if (Build.VERSION.SDK_INT >= 30) {
            WindowInsets w = decor.getRootWindowInsets();
            if (w == null) return r;
            android.graphics.Insets bars = w.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            android.graphics.Insets ime = w.getInsets(WindowInsets.Type.ime());
            r[0] = bars.top; r[1] = bars.bottom; r[2] = bars.left; r[3] = bars.right; r[4] = ime.bottom;
        } else {
            @SuppressWarnings("deprecation")
            WindowInsets w = decor.getRootWindowInsets();
            if (w == null) return r;
            r[0] = w.getSystemWindowInsetTop(); r[1] = w.getSystemWindowInsetBottom();
            r[2] = w.getSystemWindowInsetLeft(); r[3] = w.getSystemWindowInsetRight();
        }
        return r;
    }

    public void toast(final String text) {
        runOnUiThread(() -> Toast.makeText(this, text, Toast.LENGTH_SHORT).show());
    }

    /** 0 follow the phone, 1 landscape (either way up), 2 portrait. */
    public void setOrientation(final int o) {
        runOnUiThread(() -> setRequestedOrientation(o == 1 ? android.content.pm.ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE
                : o == 2 ? android.content.pm.ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT
                : android.content.pm.ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED));
    }

    public void moveToBack() {
        runOnUiThread(() -> moveTaskToBack(true));
    }

    @SuppressWarnings("deprecation")
    public void setViewing(final boolean on) {
        runOnUiThread(() -> {
            if (on) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            View decor = getWindow().getDecorView();
            if (Build.VERSION.SDK_INT >= 30) {
                WindowInsetsController c = decor.getWindowInsetsController();
                if (c != null) {
                    if (on) {
                        c.hide(WindowInsets.Type.systemBars());
                        c.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
                    } else {
                        c.show(WindowInsets.Type.systemBars());
                    }
                }
            } else {
                decor.setSystemUiVisibility(on ? (View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY | View.SYSTEM_UI_FLAG_LAYOUT_STABLE) : 0);
            }
        });
    }

    /** Copy a received file to Downloads/PortlessVNC; returns a description of where. */
    @SuppressWarnings("deprecation")
    public String saveToDownloads(String path, String name) {
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                ContentValues v = new ContentValues();
                v.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
                v.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/PortlessVNC");
                Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
                if (uri == null) return null;
                try (InputStream in = new FileInputStream(path); OutputStream out = getContentResolver().openOutputStream(uri)) {
                    copy(in, out);
                }
            } else {
                File dir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PortlessVNC");
                dir.mkdirs();
                try (InputStream in = new FileInputStream(path); OutputStream out = new java.io.FileOutputStream(new File(dir, name))) {
                    copy(in, out);
                }
            }
            new File(path).delete();
            return "Downloads/PortlessVNC/" + name;
        } catch (Exception e) {
            return null;
        }
    }

    private static void copy(InputStream in, OutputStream out) throws java.io.IOException {
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
    }

    /** Invisible view that owns the on-screen keyboard and forwards what is typed. */
    static class KeyInput extends View {
        private String composing = "";

        KeyInput(Context c) {
            super(c);
            setFocusable(true);
            setFocusableInTouchMode(true);
        }

        @Override
        public boolean onCheckIsTextEditor() {
            return true;
        }

        private void typeText(CharSequence t) {
            if (t != null && t.length() > 0) nativeEvent(1, 0, t.toString(), null);
        }

        private void backspaces(int n) {
            for (int i = 0; i < n; i++) {
                nativeEvent(2, KeyEvent.KEYCODE_DEL, null, null);
                nativeEvent(3, KeyEvent.KEYCODE_DEL, null, null);
            }
        }

        @Override
        public InputConnection onCreateInputConnection(EditorInfo out) {
            // a plain, suggestion-free keyboard: every key is sent as it is typed
            out.inputType = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;
            out.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI | EditorInfo.IME_FLAG_NO_FULLSCREEN | EditorInfo.IME_ACTION_NONE;
            composing = "";
            return new BaseInputConnection(this, false) {
                @Override
                public boolean commitText(CharSequence text, int pos) {
                    String t = text == null ? "" : text.toString();
                    if (!composing.isEmpty() && t.startsWith(composing)) {
                        typeText(t.substring(composing.length()));
                    } else {
                        backspaces(composing.length());
                        typeText(t);
                    }
                    composing = "";
                    return true;
                }

                @Override
                public boolean setComposingText(CharSequence text, int pos) {
                    String t = text == null ? "" : text.toString();
                    if (t.startsWith(composing)) {
                        typeText(t.substring(composing.length()));
                    } else {
                        backspaces(composing.length());
                        typeText(t);
                    }
                    composing = t;
                    return true;
                }

                @Override
                public boolean finishComposingText() {
                    composing = "";
                    return true;
                }

                @Override
                public boolean deleteSurroundingText(int before, int after) {
                    backspaces(before);
                    return true;
                }

                @Override
                public boolean sendKeyEvent(KeyEvent e) {
                    int u = e.getUnicodeChar();
                    String ch = u > 0 ? String.valueOf((char) u) : null;
                    if (e.getAction() == KeyEvent.ACTION_DOWN) nativeEvent(2, e.getKeyCode(), ch, null);
                    else if (e.getAction() == KeyEvent.ACTION_UP) nativeEvent(3, e.getKeyCode(), ch, null);
                    return true;
                }
            };
        }

        @Override
        public boolean onKeyPreIme(int keyCode, KeyEvent e) {
            // Back while the keyboard is up just closes the keyboard
            if (keyCode == KeyEvent.KEYCODE_BACK && e.getAction() == KeyEvent.ACTION_UP) {
                nativeEvent(7, 0, null, null);
            }
            return super.onKeyPreIme(keyCode, e);
        }
    }
}
