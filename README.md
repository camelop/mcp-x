![MCP-X Logo](logo.png)

# MCP-X

A single-file multi-client MCP gateway with per-tool access control. The entire implementation lives in `mcp_x.py`.

```
                        MCP-X (:9000)
                     ┌─────────────────┐
 ┌───────┐  auth     │  FastAPI REST   │
 │ alice ├──token──> │  /register_*    │
 └───┬───┘           │  /update_*      │
     │               │  /get_*         │
     │  MCP          ├─────────────────┤          ┌──────────┐
     └──protocol──>  │   FastMCP       │──proxy──>│ server_a │ <── owned by alice
                     │   /mcp          │          └──────────┘
 ┌───────┐  MCP      │  ┌────────────┐ │          ┌──────────┐
 │  bob  ├────────>  │  │ middleware │ │──proxy──>│ server_b │ <── owned by bob
 └───────┘           │  │ filter by  │ │          └──────────┘
                     │  │ allow list │ │
                     │  └────────────┘ │
                     └─────────────────┘
```

Given `server_a` has tools `[a-tool-qwe, a-tool-zxc]` and `server_b` has `[b-tool-asd, b-tool-jkl]`, with the example config below, each client sees:

```
 alice (owns server_a)
   server_a: a-tool-qwe, a-tool-zxc        (owner -- full access)
   server_b: b-tool-asd                    (allowed: ["b-*a*"])
   ─────────────────────────────────────
   tools:    a-tool-qwe, a-tool-zxc, b-tool-asd

 bob (owns server_b)
   server_b: b-tool-asd, b-tool-jkl        (owner -- full access)
   server_a: a-tool-qwe, a-tool-zxc        (allowed: ["*"])
   ─────────────────────────────────────
   tools:    b-tool-asd, b-tool-jkl, a-tool-qwe, a-tool-zxc
```

Each client authenticates with a Bearer token and can bring a list of their own MCP servers, then share specific tools from those servers with other clients. Clients talk MCP at `/mcp`; the middleware filters which tools each client can see/call based on `config.toml` policies. Server owners always have full access to their own tools.

## Quick Start

```bash
uv sync
# start the gateway (default port 9000)
uv run python mcp_x.py
# or with a custom port
uv run python mcp_x.py --port 8080
```

## Testing

1. Start the example backend MCP servers:
```bash
uv run python run_example_mcp_servers.py
```

2. Start the gateway:
```bash
uv run python mcp_x.py
```

3. Verify with:
   - **Swagger UI** -- open `http://localhost:9000/docs` to inspect and try the REST endpoints
   - **MCP Inspector** -- `npx @anthropic-ai/mcp-inspector` then connect to `http://localhost:9000/mcp` with a Bearer token from `config.toml` (e.g. `123` for alice)

## Configuration

Copy `config.example.toml` to `config.toml` and edit it. The file has three sections:

```toml
# 1. Clients: name -> static auth token
[clients.alice]
auth_token = "123"

[clients.bob]
auth_token = "456"

# 2. MCP servers: name -> upstream URL + which client registered it
[mcp_servers.server_a]
url = "http://localhost:9100"
from_client = "alice"          # alice owns server_a

[mcp_servers.server_b]
url = "http://localhost:9101"
from_client = "bob"

# 3. Access control: server_name -> { client -> [tool_patterns] }
#    Patterns use fnmatch syntax: * ? [seq] [!seq]
[allow.server_a]
bob = ["*"]                            # bob can use all tools on server_a
charlie = ["tool_0", "tool_1*", "*_2"] # charlie gets specific tools

[allow.server_b]
alice = ["b-*a*"]                      # alice gets matching tools on server_b
```

Server owners (the `from_client` field) always have full access to their own server's tools -- no `[allow]` entry needed.

**Note on duplicate tool names:** If a client has access to multiple servers that expose a tool with the same name, only one will be used (from whichever server is matched first). Tools from owned servers are always checked before shared ones.

### Live Reload

`config.toml` is checked for changes on every request (throttled to once per second). Edit it while the server is running and changes take effect immediately -- no restart needed.

The file is also written to by the server when clients register via the REST API (`POST /register_client`, `/register_mcp_server`, `/update_access_control`). Manually-configured client tokens in the file are preserved across these writes.

## REST API

All endpoints (except `/register_client`) require a `Bearer` token in the `Authorization` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/register_client` | Create a new client. Returns a `client_id` and a JWT `auth_token` (1h expiry). |
| `POST` | `/register_mcp_server` | Register an upstream MCP server URL. The calling client becomes the owner. |
| `POST` | `/update_access_control` | Grant or revoke another client's access to tools on your servers. Accepts `client_id` and `server_access: {server_name: [tool_patterns]}`. |
| `GET`  | `/get_access_control` | View current access policies for all servers you own. |

The MCP endpoint is at `/mcp` (stateless HTTP). Clients use standard MCP protocol to list and call tools.

## How It Works

- **Server name hashing** -- server names are stored internally as SHA-256 hashes. This avoids collisions when FastMCP concatenates server and tool names with underscores (e.g. a server named `foo` with tool `bar_baz` vs server `foo_bar` with tool `baz`).

- **Tool name rewriting** -- the middleware strips the internal server-hash prefix before returning tools to clients, so clients see clean tool names. On `call_tool`, the middleware re-adds the correct prefix and tries each allowed server until one succeeds.

- **JWT** -- `POST /register_client` issues a JWT (1h expiry). The signing secret is auto-generated and saved to `jwt_secret` on first run.