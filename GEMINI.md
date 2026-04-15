# Galaxy Project Context

## Project Overview
**Galaxy** is a Burp Suite extension designed to facilitate the testing of encrypted HTTP traffic by providing on-the-fly decryption and encryption. It allows security researchers to view and modify encrypted data as plaintext within Burp's standard tools (Proxy, Repeater, Intruder, etc.) using custom-written hooks.

### Key Technologies
- **Language**: Java 17+ (Targeting Java 17/21 compatibility).
- **Build System**: Gradle.
- **Hooking Engines**:
    - **JavaScript**: Powered by GraalJS.
    - **Python**: Supports both GraalPy (via GraalVM) and Jython.
    - **Java**: Supports compiling and loading `.java` files as hooks.
- **UI Framework**: Java Swing with RSyntaxTextArea for script editing.
- **Key Libraries**: Montoya API, Bouncy Castle (for crypto), Lombok, GraalVM SDK, SnakeYAML.

### Core Architecture
- `org.m2sec.abilities`: Contains the primary logic for intercepting Burp traffic (`HttpHookHandler`) and providing context menus (`MasterContextMenuProvider`).
- `org.m2sec.core.httphook`: Manages the different script engines (JS, Python, Java) and orchestrates the hooking lifecycle.
- `org.m2sec.core.models`: Provides high-level abstractions for `Request` and `Response` objects, making them easier to manipulate within scripts compared to raw Montoya API objects.
- `org.m2sec.core.utils`: A comprehensive suite of static utility classes:
    - `CryptoUtil`: Symmetric (AES, DES, SM4) and Asymmetric (RSA, SM2) encryption.
    - `CodeUtil`: Encoding/decoding (Base64, Hex, URL).
    - `HashUtil`: Hashing (MD5, SHA, SM3).
    - `JsonUtil`: JSON parsing and serialization using Gson.
- `org.m2sec.panels`: Implements the Swing-based GUI for plugin configuration and script management.

## Building and Running

### Build Command
To generate the plugin JAR (Fat JAR containing all dependencies):
```bash
./gradlew shadowJar
```
The output JAR will be located in `build/libs/`. The specific engine included (all/js/graalpy) is controlled by the `optionalHooker` property in `build.gradle`.

### Installation
1. Open Burp Suite.
2. Navigate to `Extensions` -> `Installed`.
3. Click `Add`, select `Java` as the extension type, and pick the generated JAR file.

### Prerequisites
- JDK 17 or 21.
- Burp Suite version >= `v2023.10.3.7`.

## Development Conventions

### Hook Script Implementation
Users can write scripts in JS, Python, or Java. Each script must implement the following standard hook functions:
- `hook_request_to_burp(request)`: Decrypt request data when it arrives from the client.
- `hook_request_to_server(request)`: Encrypt request data before it is sent to the server.
- `hook_response_to_burp(response)`: Decrypt response data when it arrives from the server.
- `hook_response_to_client(response)`: Encrypt response data before it is sent back to the client.

### Coding Style & Patterns
- **Utility-First**: Leverage the static methods in `org.m2sec.core.utils` for any crypto or encoding needs.
- **Model Abstraction**: Always use the models in `org.m2sec.core.models` when interacting with HTTP messages in the core logic.
- **Thread Safety**: The extension handles concurrent requests; use `HttpHookThreadData` for per-request state if needed.
- **Auto-completion**: When adding new utility methods, register them in `CodeFileHookerPanel.createCompletionProvider()` to provide IDE-like features in the script editor.

### Testing
- Existing tests are located in `src/test/java`.
- **Note**: `TempTest.java` is often used for quick verification of crypto logic.
- Always verify crypto changes against known-good implementations (e.g., matching a web-side CryptoJS implementation).

## Important Files
- `src/main/java/org/m2sec/Galaxy.java`: The main entry point for the Burp extension.
- `src/main/java/org/m2sec/core/httphook/IHttpHooker.java`: The base class defining the hooking orchestration logic.
- `src/main/java/org/m2sec/core/utils/CryptoUtil.java`: The central point for all cryptographic operations.
- `src/main/resources/templates/`: Contains default templates for new hook scripts.
- `src/main/resources/examples/`: Provides numerous example scripts for common encryption scenarios (AES, RSA, SM2, etc.).
