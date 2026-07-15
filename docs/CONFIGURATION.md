# Configuration

Diaphora MCP is a local stdio server. The MCP client starts the Python process and communicates over stdin/stdout; diagnostic logs are written separately by the project logger.

## Environment variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `IDAT_PATH` | Yes for headless | Absolute path to `idat.exe` or `idat64.exe` |
| `DIAPHORA_DIR` | Yes for headless/diff | Directory containing the Diaphora scripts |
| `DIAPHORA_OUTPUT_ROOT` | Recommended | Root inside which new export targets are allowed |
| `DIAPHORA_PYTHON` | Optional | Python interpreter for the Diaphora diff process |

Use an output root dedicated to generated files. The server refuses output paths outside the configured root and refuses overwriting an existing target.

## Windows example

PowerShell:

```powershell
$env:IDAT_PATH = 'C:\Program Files\IDA Professional 9.3\idat.exe'
$env:DIAPHORA_DIR = 'C:\Program Files\IDA Professional 9.3\plugins\diaphora'
$env:DIAPHORA_OUTPUT_ROOT = 'C:\diaphora-outputs'
```

In JSON, either use forward slashes or escape backslashes:

```json
{
  "command": "python",
  "args": ["C:/src/diaphora-mcp/diaphora_mcp_server.py"],
  "env": {
    "IDAT_PATH": "C:/Program Files/IDA Professional 9.3/idat.exe",
    "DIAPHORA_DIR": "C:/Program Files/IDA Professional 9.3/plugins/diaphora",
    "DIAPHORA_OUTPUT_ROOT": "C:/diaphora-outputs"
  }
}
```

## GUI integration

`auto` can use the active `ida_mcp` HTTP integration or the optional legacy XML-RPC listener on port `28652`. The upstream `ida-pro-mcp`/`idalib-mcp` server is a separate IDA inspection service; it does not replace this Diaphora server.

Use `gui` only when the requested IDB is open in the GUI and you explicitly want that backend. Use `headless` for repeatable comparisons.

## Restarting

After changing Python code or environment variables, restart the MCP server from the client. If the process was started manually on Windows, stop only the Diaphora server process and start it again; do not terminate unrelated `idalib-mcp` or IDA processes.
