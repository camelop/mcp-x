#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
mcp_x.py

Author: stneng, littleround, luke
Source: https://github.com/camelop/mcp-x

A single-file multi-client MCP gateway with per-tool access control.
"""

import os
import logging
import argparse
import asyncio
import hashlib
import uuid
import time
import secrets
import fnmatch
from dataclasses import dataclass
from itertools import chain

import toml
import jwt
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.proxy import ProxyClient

# ============================================================
# Configuration
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] [%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _load_or_generate_jwt_secret() -> str:
    """Load JWT secret from 'jwt_secret' file, or generate and save a new one."""
    secret_file = "jwt_secret"
    try:
        with open(secret_file, "r") as f:
            secret = f.read().strip()
            if secret:
                return secret
    except FileNotFoundError:
        pass
    secret = secrets.token_urlsafe(32)
    with open(secret_file, "w") as f:
        f.write(secret)
    logger.info(f"Generated new JWT secret and saved to {secret_file}")
    return secret


JWT_SECRET = _load_or_generate_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "mcp-x"
JWT_AUDIENCE = "mcp-x-client"

CONFIG_FILE = "config.toml"

server_registration_lock = asyncio.Lock()
access_control_lock = asyncio.Lock()

# Granular access control: client_id -> {server_hash: [tool_patterns]}
access_control: dict = {}
server_configs: dict = {}  # server_hash -> {"url": ...}
dummy_server_config = {
    "_dummy_0": {"url": "http://0.0.0.0"},
    "_dummy_1": {"url": "http://0.0.0.0"},
}  # Used to ensure FastMCP treats it as multi-server
server_owners: dict = {}  # server_hash -> client_name
server_name_map: dict[str, str] = {}  # server_hash -> original server_name
client_tokens: dict[str, str] = {}  # auth_token -> client_name


def _hash_name(name: str) -> str:
    """SHA-256 hash of a server name, used as internal key to avoid underscore collisions."""
    return hashlib.sha256(name.encode()).hexdigest()


def _display_name(server_hash: str) -> str:
    """Return the original server name for a hash, or the hash itself as fallback."""
    return server_name_map.get(server_hash, server_hash)


_config_mtime: float = 0
_last_config_check: float = 0
_CONFIG_CHECK_INTERVAL: float = 1.0


# ============================================================
# Config File Loading
# ============================================================


def _refresh_proxy_client_factory(server_configs: dict):
    # add dummy if less than 2 servers to avoid FastMCP treating it as single-server and skipping middleware
    s = {
        **dummy_server_config,
        **server_configs,
    }
    mcp_server._tool_manager.client_factory = lambda: ProxyClient(s).new()  # type: ignore


def load_config_from_file(filepath: str = CONFIG_FILE):
    """Load policy and server configuration from a TOML file."""
    global access_control, server_configs, server_owners, server_name_map, client_tokens

    config = toml.load(filepath)

    # Load clients
    new_client_tokens: dict[str, str] = {}
    for client_name, client_info in config.get("clients", {}).items():
        token = client_info.get("auth_token")
        if token:
            new_client_tokens[token] = client_name

    # Load MCP servers — store under hashed keys
    new_server_configs: dict = {}
    new_server_owners: dict = {}
    new_name_map: dict[str, str] = {}
    for server_name, server_info in config.get("mcp_servers", {}).items():
        h = _hash_name(server_name)
        new_server_configs[h] = {"url": server_info["url"]}
        new_server_owners[h] = server_info["from_client"]
        new_name_map[h] = server_name

    # Load access control: config format {server: {client: [patterns]}}
    # Internal format: {client: {server_hash: [patterns]}}
    new_access_control: dict = {}
    for server_name, clients in config.get("allow", {}).items():
        h = _hash_name(server_name)
        for client_name, patterns in clients.items():
            new_access_control.setdefault(client_name, {})[h] = patterns

    client_tokens = new_client_tokens
    server_configs = new_server_configs
    server_owners = new_server_owners
    server_name_map = new_name_map
    access_control = new_access_control

    logger.info(
        f"Loaded config from {filepath}: "
        f"{len(new_client_tokens)} clients, "
        f"{len(new_server_configs)} servers, "
        f"{len(new_access_control)} client policies"
    )


def _flush_config_to_file(filepath: str = CONFIG_FILE):
    """Write current in-memory state back to the config TOML file.

    For clients: preserves tokens already in the file; only writes new ones.
    For mcp_servers and allow: overwrites from in-memory state.
    """
    global _config_mtime

    # Read existing config to check which clients already have persisted tokens
    try:
        existing_config = toml.load(filepath)
    except (FileNotFoundError, toml.TomlDecodeError):
        existing_config = {}

    existing_clients = existing_config.get("clients", {})

    config: dict = {}

    # Clients: keep existing file tokens; add new ones from in-memory
    clients_section: dict = {}
    for token, client_name in client_tokens.items():
        if client_name in existing_clients:
            clients_section[client_name] = existing_clients[client_name]
        else:
            clients_section[client_name] = {"auth_token": token}
    if clients_section:
        config["clients"] = clients_section

    # MCP servers: reverse hashes to original names via server_name_map
    servers_section: dict = {}
    for srv_hash, server_info in server_configs.items():
        if srv_hash == "dummy":
            continue
        original_name = _display_name(srv_hash)
        servers_section[original_name] = {
            "url": server_info["url"],
            "from_client": server_owners.get(srv_hash, ""),
        }
    if servers_section:
        config["mcp_servers"] = servers_section

    # Access control: internal {client: {server_hash: [patterns]}} -> config {server_name: {client: [patterns]}}
    allow_section: dict = {}
    for client_name, client_access in access_control.items():
        for srv_hash, patterns in client_access.items():
            original_name = _display_name(srv_hash)
            if original_name not in allow_section:
                allow_section[original_name] = {}
            allow_section[original_name][client_name] = patterns
    if allow_section:
        config["allow"] = allow_section

    with open(filepath, "w") as f:
        toml.dump(config, f)

    _config_mtime = os.path.getmtime(filepath)
    logger.info(f"Flushed config to {filepath}")


def _ensure_config_loaded():
    """Check if config.toml has changed and reload if needed."""
    global _config_mtime, _last_config_check

    now = time.time()
    if now - _last_config_check < _CONFIG_CHECK_INTERVAL:
        return
    _last_config_check = now

    try:
        mtime = os.path.getmtime(CONFIG_FILE)
        if mtime != _config_mtime:
            _config_mtime = mtime
            load_config_from_file()
            if server_configs:
                _refresh_proxy_client_factory(server_configs)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.error(f"Error reloading config: {e}")


# ============================================================
# Utility — Pattern Matching
# ============================================================


def _get_owned_hashes(client_id: str) -> set[str]:
    """Return the set of server hashes owned by a given client."""
    return {h for h, owner in server_owners.items() if owner == client_id}


def _tool_matches_patterns(tool_name: str, patterns: list[str]) -> bool:
    """Check if a tool name matches any of the allowed patterns.

    Patterns use fnmatch-style matching:
      - ["*"] matches all tools
      - ["tool_*"] matches tools starting with "tool_"
      - ["*_public"] matches tools ending with "_public"
      - ["tool_0", "tool_1"] matches exact names
    """
    return any(fnmatch.fnmatch(tool_name, p) for p in patterns)


# ============================================================
# Schema Definitions
# ============================================================


class ClientRegistrationResponse(BaseModel):
    client_id: str
    auth_token: str
    expires_in_seconds: int


class MCPServerRegistration(BaseModel):
    url: str


class MCPServerRegistrationResponse(BaseModel):
    server_id: str


class AccessControlUpdate(BaseModel):
    client_id: str
    server_access: dict  # {server_name: [tool_patterns]}


# ============================================================
# Services — JWT Authentication
# ============================================================


@dataclass
class AuthenticatedUser:
    client_id: str
    scopes: list[str]


def create_jwt_token(
    client_id: str,
    scopes: list[str] | None = None,
    expires_in: int = 3600,
) -> str:
    now = time.time()
    payload = {
        "sub": client_id,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "scopes": scopes or ["list_tools", "call_tools"],
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )


def _authenticate_token(token: str) -> AuthenticatedUser:
    """Authenticate a bearer token. Checks config-based tokens first, then JWT."""
    if token in client_tokens:
        return AuthenticatedUser(
            client_id=client_tokens[token],
            scopes=["list_tools", "call_tools"],
        )
    payload = verify_jwt_token(token)
    return AuthenticatedUser(
        client_id=payload["sub"],
        scopes=payload.get("scopes", []),
    )


security = HTTPBearer()


async def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> AuthenticatedUser:
    _ensure_config_loaded()
    try:
        user = _authenticate_token(credentials.credentials)
        logger.info(f"Authenticated user: {user.client_id} with scopes: {user.scopes}")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Authentication failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid authentication token")


def _extract_caller_from_mcp_request() -> AuthenticatedUser:
    """Extract and verify token from the current MCP HTTP request.

    Used inside FastMCP middleware where FastAPI dependencies are not available.
    """
    request = get_http_request()
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise Exception("Missing Bearer token")
    token = auth_header.removeprefix("Bearer ")
    return _authenticate_token(token)


# ============================================================
# FastMCP Middleware
# ============================================================


def _authenticate_mcp_caller(operation: str) -> AuthenticatedUser:
    """Reload config if stale, then extract and authenticate the caller from the current MCP request."""
    _ensure_config_loaded()
    caller = _extract_caller_from_mcp_request()
    logger.info(f"{operation} requested by: {caller.client_id}")
    return caller


class ListingFilterMiddleware(Middleware):
    async def on_list_tools(self, context: MiddlewareContext, call_next):
        try:
            caller = _authenticate_mcp_caller("list_tools")
        except Exception as e:
            logger.warning(f"Unauthenticated list_tools request: {e}")
            return []

        result = await call_next(context)
        allowed_access = access_control.get(caller.client_id, {})

        # Servers owned by this client: always grant full access
        owned_servers = _get_owned_hashes(caller.client_id)

        filtered_tools = []
        seen_tool_names: set[str] = set()

        for tool in result:
            for server_name in chain(owned_servers, allowed_access):
                if not tool.name.startswith(f"{server_name}_"):
                    continue
                clean_tool_name = tool.name[len(f"{server_name}_") :]
                if clean_tool_name in seen_tool_names:
                    continue
                # Owner gets all tools; others checked against patterns
                if server_name in owned_servers or _tool_matches_patterns(
                    clean_tool_name, allowed_access.get(server_name, [])
                ):
                    clean_tool = tool.copy()
                    clean_tool.name = clean_tool_name
                    filtered_tools.append(clean_tool)
                    seen_tool_names.add(clean_tool_name)
                    logger.debug(
                        f"Added tool '{clean_tool_name}' from server '{_display_name(server_name)}' for {caller.client_id}"
                    )

        logger.info(
            f"Filtered tools for {caller.client_id}: {len(filtered_tools)} tools (from {len(result)}), removed server prefixes"
        )
        return filtered_tools


class ToolCallFilterMiddleware(Middleware):
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        try:
            caller = _authenticate_mcp_caller(f"call_tool({context.message.name})")
        except Exception as e:
            logger.warning(f"Unauthenticated call_tool request: {e}")
            raise Exception("Authentication required")

        allowed_access = access_control.get(caller.client_id, {})

        # Servers owned by this client: always grant full access
        owned_servers = _get_owned_hashes(caller.client_id)

        if not allowed_access and not owned_servers:
            logger.warning(f"No access control found for caller: {caller.client_id}")
            raise Exception(f"Access denied for caller: {caller.client_id}")

        # Check owned servers first, then policy-allowed servers
        for server_name in chain(
            owned_servers, (s for s in allowed_access if s not in owned_servers)
        ):
            is_owner = server_name in owned_servers
            if is_owner or _tool_matches_patterns(
                context.message.name, allowed_access.get(server_name, [])
            ):
                prefixed_tool_name = f"{server_name}_{context.message.name}"
                original_tool_name = context.message.name
                context.message.name = prefixed_tool_name

                try:
                    result = await call_next(context)
                    logger.debug(
                        f"Successfully called tool '{original_tool_name}' on server '{_display_name(server_name)}' for {caller.client_id}"
                    )
                    return result
                except Exception as e:
                    logger.debug(
                        f"Tool '{original_tool_name}' not found on server '{_display_name(server_name)}': {e}"
                    )
                    context.message.name = original_tool_name
                    continue

        logger.error(
            f"Tool '{context.message.name}' not found on any allowed servers or access denied for {caller.client_id}"
        )
        raise Exception(f"Tool '{context.message.name}' not found or access denied")


# ============================================================
# FastAPI Routes
# ============================================================

router = APIRouter()


@router.post("/register_client", response_model=ClientRegistrationResponse)
def register_client():
    global client_tokens
    client_id = str(uuid.uuid4())
    auth_token = create_jwt_token(client_id)
    client_tokens[auth_token] = client_id
    _flush_config_to_file()
    return ClientRegistrationResponse(
        client_id=client_id, auth_token=auth_token, expires_in_seconds=3600
    )


@router.post("/register_mcp_server", response_model=MCPServerRegistrationResponse)
async def register_mcp_server(
    mcp_server_registration: MCPServerRegistration,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
):
    logger.info(f"MCP server registration requested by: {current_user.client_id}")
    server_id = str(uuid.uuid4())
    server_hash = _hash_name(server_id)

    async with server_registration_lock:
        global server_configs, server_owners, server_name_map
        server_configs[server_hash] = {"url": mcp_server_registration.url}
        server_owners[server_hash] = current_user.client_id
        server_name_map[server_hash] = server_id
        _refresh_proxy_client_factory(server_configs)
        _flush_config_to_file()

    logger.info(f"Registered MCP server '{server_id}' at {mcp_server_registration.url}")
    return MCPServerRegistrationResponse(server_id=server_id)


@router.post("/update_access_control")
async def update_access_control(
    access_update: AccessControlUpdate,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
):
    logger.info(
        f"Access control update requested by: {current_user.client_id} for client: {access_update.client_id}"
    )

    owned_hashes = _get_owned_hashes(current_user.client_id)
    owned_names = {_display_name(h) for h in owned_hashes}

    if not owned_hashes:
        logger.warning(f"User {current_user.client_id} doesn't own any servers")
        raise HTTPException(
            status_code=403, detail="You don't own any servers to grant access to"
        )

    # Incoming keys are original names — validate against owned names
    invalid_servers = set(access_update.server_access.keys()) - owned_names
    if invalid_servers:
        logger.warning(
            f"User {current_user.client_id} tried to update access for servers they don't own: {invalid_servers}"
        )
        raise HTTPException(
            status_code=403,
            detail=f"You don't own these servers: {', '.join(invalid_servers)}. You can only update access for servers you own: {', '.join(owned_names)}",  # type: ignore
        )

    async with access_control_lock:
        global access_control
        access_control.setdefault(access_update.client_id, {})

        # Convert incoming names to hashes for comparison
        incoming_hashes = {_hash_name(name) for name in access_update.server_access}

        current_client_access = access_control[access_update.client_id]
        servers_to_remove = [
            h
            for h in current_client_access
            if h in owned_hashes and h not in incoming_hashes
        ]

        for h in servers_to_remove:
            del access_control[access_update.client_id][h]
            logger.info(
                f"Removed access for client '{access_update.client_id}' to server '{_display_name(h)}' (not in update request)"
            )

        for name, tool_access in access_update.server_access.items():
            h = _hash_name(name)
            # Normalize: ensure tool_access is always a list of patterns
            if isinstance(tool_access, str):
                tool_access = [tool_access]
            access_control[access_update.client_id][h] = tool_access
            logger.info(
                f"Updated access for client '{access_update.client_id}' to server '{name}': {tool_access}"
            )

        _flush_config_to_file()

    return {
        "message": f"Successfully updated access control for client '{access_update.client_id}'",
    }


@router.get("/get_access_control")
async def get_access_control_route(
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
):
    logger.info(f"Access control view requested by: {current_user.client_id}")

    owned_hashes = _get_owned_hashes(current_user.client_id)

    filtered_access = {}
    for client_name, client_access in access_control.items():
        filtered_client_access = {
            _display_name(h): acc
            for h, acc in client_access.items()
            if h in owned_hashes
        }
        if filtered_client_access:
            filtered_access[client_name] = filtered_client_access

    owned_names = [_display_name(h) for h in owned_hashes]
    return {"owned_servers": owned_names, "access_control": filtered_access}


# ============================================================
# Application Assembly & Entry Point
# ============================================================

# Load initial config from file
try:
    load_config_from_file()
    _config_mtime = os.path.getmtime(CONFIG_FILE)
except FileNotFoundError:
    logger.warning(f"Config file {CONFIG_FILE} not found, starting with defaults")
except Exception as e:
    logger.error(f"Error loading initial config: {e}")

mcp_server = FastMCP.as_proxy(
    {
        **dummy_server_config,
        **server_configs,
    },
    name="MCP-X",
)
mcp_server.add_middleware(ListingFilterMiddleware())
mcp_server.add_middleware(ToolCallFilterMiddleware())

mcp_app = mcp_server.http_app(path="/", stateless_http=True)

app = FastAPI(title="MCP-X API", lifespan=mcp_app.lifespan)
app.include_router(router)
app.mount("/mcp", mcp_app)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP-X Proxy Server")
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Port to run the server on (default: %(default)s)",
    )
    args = parser.parse_args()

    logger.info(f"Starting MCP-X server on port {args.port}")
    uvicorn.run(
        app, host="0.0.0.0", port=args.port, log_level="error", ws="websockets-sansio"
    )
