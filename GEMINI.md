# Galaxy Project Context

## Project Overview
**Galaxy** is a powerful Burp Suite extension designed to simplify testing encrypted HTTP traffic. It allows security researchers to decrypt and encrypt traffic on-the-fly using custom scripts, making encrypted data appear as plaintext within Burp's standard tools (Proxy, Repeater, Intruder, etc.).

### Key Technologies
- **Language**: Java 17+ (Targeting compatibility with Java 17/21).
- **Build System**: Gradle.
- **Hooking Engines**: 
    - **JavaScript**: Powered by GraalJS.
    - **Python**: Supports both GraalPy and Jython.
    - **Java**: Supports compiling and loading Java files as hooks.
- **UI Framework**: Java Swing (integrated with Burp's Montoya API).
- **Key Libraries**: Montoya API, RSyntaxTextArea (for code editing), Bouncy Castle (for crypto), Lombok.

### Architecture
- `org.m2sec.abilities`: Core Burp functionalities like HTTP handlers, context menus, and payload generators.
- `org.m2sec.core.httphook`: The orchestration layer for different script engines (JS, Python, Java).
- `org.m2sec.core.utils`: Comprehensive utility classes for encoding (`CodeUtil`), crypto (`CryptoUtil`), hashing (`HashUtil`), and JSON processing (`JsonUtil`).
- `org.m2sec.panels`: Swing-based GUI components for the plugin's configuration tabs.

## Building and Running

### Build Command
To generate the plugin JAR (Fat JAR containing all dependencies):
```bash
./gradlew shadowJar
```
The output will be located in `build/libs/Galaxy-<version>-<engine>.jar`.

### Installation
1. Open Burp Suite.
2. Go to `Extensions` -> `Installed`.
3. Click `Add`, select `Java` as the extension type, and pick the generated JAR file.

### Prerequisites
- JDK 17 or 21.
- Burp Suite version >= `v2023.10.3.7`.

## Development Conventions

### Code Style & Patterns
- **Utility-First**: Extensive use of static utility classes in `org.m2sec.core.utils`. When adding encoding/decoding or crypto logic, place it there.
- **Hook Methods**: Scripts (JS/Python) should implement standard hook functions:
    - `hook_request_to_burp(request)`
    - `hook_request_to_server(request)`
    - `hook_response_to_burp(response)`
    - `hook_response_to_client(response)`
- **Thread Safety**: The extension handles concurrent requests; use `HttpHookThreadData` for per-request state.

### UI Modifications
- The editor uses `RSyntaxTextArea`. Configurations for line wrapping, auto-completion, and themes are handled in `CodeFileHookerPanel.java`.
- **Auto-completion**: New utility methods should be registered in `CodeFileHookerPanel.createCompletionProvider()` using the `Class.method` format for better filtering.

### Testing
- Existing tests are located in `src/test/java`.
- Always verify crypto logic changes against real-world test cases (e.g., matching CryptoJS or web-side implementation outputs).

## Important Files
- `build.gradle`: Project dependencies and shadowJar configuration.
- `src/main/java/org/m2sec/core/utils/CryptoUtil.java`: Main entry point for symmetric and asymmetric encryption.
- `src/main/java/org/m2sec/panels/httphook/CodeFileHookerPanel.java`: Implementation of the script editor and its auto-completion logic.
- `src/main/resources/templates/`: Default templates for the various hook engines.
