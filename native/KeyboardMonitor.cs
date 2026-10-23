using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PIIGuardNative {
    class KeyboardMonitor {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public UIntPtr dwExtraInfo;
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        [DllImport("user32.dll")]
        private static extern short GetKeyState(int vKey);

        [DllImport("user32.dll")]
        private static extern sbyte GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage([In] ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage([In] ref MSG lpMsg);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
        }

        private static string GetActiveWindowTitle() {
            try {
                IntPtr handle = GetForegroundWindow();
                if (handle == IntPtr.Zero) return "Desktop";
                StringBuilder buffer = new StringBuilder(256);
                if (GetWindowText(handle, buffer, 256) > 0) {
                    string t = buffer.ToString().Trim();
                    if (!string.IsNullOrEmpty(t)) return t;
                }
            } catch {}
            return "Desktop";
        }

        private static string MapVkToChar(uint vk) {
            bool shift = (GetAsyncKeyState(0x10) & 0x8000) != 0; // VK_SHIFT
            bool caps = (GetKeyState(0x14) & 1) != 0;         // VK_CAPITAL (Caps Lock)

            // Special control keys
            if (vk == 0x08) return "\b"; // Backspace
            if (vk == 0x0D) return "\n"; // Enter
            if (vk == 0x09) return "\t"; // Tab
            if (vk == 0x20) return " ";  // Space

            // Letters A-Z (0x41 to 0x5A)
            if (vk >= 0x41 && vk <= 0x5A) {
                char letter = (char)('a' + (vk - 0x41));
                if (shift ^ caps) {
                    letter = char.ToUpper(letter);
                }
                return letter.ToString();
            }

            // Standard Top-Row Digits (0x30 to 0x39)
            if (vk >= 0x30 && vk <= 0x39) {
                if (!shift) {
                    return ((char)('0' + (vk - 0x30))).ToString();
                } else {
                    // Shifted symbols on standard US keyboard
                    switch (vk) {
                        case 0x30: return ")";
                        case 0x31: return "!";
                        case 0x32: return "@";
                        case 0x33: return "#";
                        case 0x34: return "$";
                        case 0x35: return "%";
                        case 0x36: return "^";
                        case 0x37: return "&";
                        case 0x38: return "*";
                        case 0x39: return "(";
                    }
                }
            }

            // Numpad Digits (0x60 to 0x69)
            if (vk >= 0x60 && vk <= 0x69) {
                return ((char)('0' + (vk - 0x60))).ToString();
            }

            // Numpad operations
            if (vk == 0x6A) return "*"; // Multiply
            if (vk == 0x6B) return "+"; // Add
            if (vk == 0x6D) return "-"; // Subtract
            if (vk == 0x6E) return "."; // Decimal
            if (vk == 0x6F) return "/"; // Divide

            // Punctuation and common symbols
            switch (vk) {
                case 0xBD: return shift ? "_" : "-"; // Minus / Underscore
                case 0xBB: return shift ? "+" : "="; // Plus / Equals
                case 0xBE: return shift ? ">" : "."; // Period / Greater
                case 0xBC: return shift ? "<" : ","; // Comma / Less
                case 0xBF: return shift ? "?" : "/"; // Slash / Question
                case 0xBA: return shift ? ":" : ";"; // Semicolon / Colon
                case 0xDE: return shift ? "\"" : "'"; // Quotes
                case 0xDB: return shift ? "{" : "["; // Bracket left
                case 0xDD: return shift ? "}" : "]"; // Bracket right
                case 0xDC: return shift ? "|" : "\\"; // Backslash
                case 0xC0: return shift ? "~" : "`"; // Tilde
            }

            return "";
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN)) {
                KBDLLHOOKSTRUCT kbd = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
                uint vkCode = kbd.vkCode;

                string ch = MapVkToChar(vkCode);
                if (!string.IsNullOrEmpty(ch)) {
                    string appName = GetActiveWindowTitle();

                    // Sanitize JSON characters
                    string safeCh = ch;
                    if (safeCh == "\b") safeCh = "\\b";
                    else if (safeCh == "\n") safeCh = "\\n";
                    else if (safeCh == "\t") safeCh = "\\t";
                    else if (safeCh == "\"") safeCh = "\\\"";
                    else if (safeCh == "\\") safeCh = "\\\\";

                    string safeApp = appName.Replace("\\", "\\\\").Replace("\"", "\\\"");

                    Console.WriteLine("{\"char\":\"" + safeCh + "\",\"vk\":" + vkCode + ",\"app\":\"" + safeApp + "\"}");
                    Console.Out.Flush();
                }
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        static void Main(string[] args) {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("{\"status\":\"READY\"}");
            Console.Out.Flush();

            // Background thread to monitor parent exit via stdin closure
            Thread stdinWatcher = new Thread(() => {
                try {
                    while (Console.ReadLine() != null) {}
                } catch {}
                Environment.Exit(0);
            });
            stdinWatcher.IsBackground = true;
            stdinWatcher.Start();

            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule) {
                _hookID = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(curModule.ModuleName), 0);
            }

            if (_hookID == IntPtr.Zero) {
                Console.WriteLine("{\"status\":\"ERROR\",\"message\":\"Failed to set keyboard hook.\"}");
                Console.Out.Flush();
                return;
            }

            MSG msg;
            while (GetMessage(out msg, IntPtr.Zero, 0, 0) > 0) {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }

            UnhookWindowsHookEx(_hookID);
        }
    }
}
