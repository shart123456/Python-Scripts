import sys
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis

def analyze_apk(file_path):
    # Parse the APK file
    a = apk.APK(file_path)
    d = a.get_vm()
    dx = analysis.Analysis(d)

    print("APK Package Name:", a.get_package())
    print("APK Main Activity:", a.get_main_activity())

    # Analyze permissions
    print("\nPermissions:")
    for perm in a.get_permissions():
        print(perm)

    # Look for common vulnerabilities
    print("\nPotential vulnerabilities:")

    # Check for unencrypted HTTP communication
    unencrypted_http = "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs"
    if unencrypted_http in d.get_strings():
        print("- Unencrypted HTTP communication detected")

    # Check for World-readable and World-writable files
    world_readable = "Landroid/content/Context;->MODE_WORLD_READABLE"
    world_writable = "Landroid/content/Context;->MODE_WORLD_WRITEABLE"
    if world_readable in d.get_strings():
        print("- World-readable files detected")
    if world_writable in d.get_strings():
        print("- World-writable files detected")

    # Check for insecure WebView configurations
    webview_debug = "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled"
    if webview_debug in d.get_strings():
        print("- WebView remote debugging enabled")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_apk.py <path_to_apk>")
    else:
        analyze_apk(sys.argv[1])
