"""Spin up two test MCP servers with randomly-named tools."""

import asyncio
import random
import string
import uvicorn
from fastmcp import FastMCP
from starlette.middleware.cors import CORSMiddleware


def _random_name(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def create_test_server(name: str, prefix: str, num_tools: int = 5) -> FastMCP:
    server = FastMCP(name=name)

    for _ in range(num_tools):
        tool_name = f"{prefix}-{_random_name()}"

        @server.tool(name=tool_name)
        def tool_fn() -> str:
            return tool_name

    return server


async def main():
    server_a = create_test_server("server-a", prefix="a", num_tools=5)
    server_b = create_test_server("server-b", prefix="b", num_tools=5)

    app_a = server_a.http_app(path="/", stateless_http=True)
    app_a.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )
    app_b = server_b.http_app(path="/", stateless_http=True)
    app_b.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )

    config_a = uvicorn.Config(app_a, host="0.0.0.0", port=9001)
    config_b = uvicorn.Config(app_b, host="0.0.0.0", port=9002)

    print("Starting server-a on port 9001")
    print("Starting server-b on port 9002")

    await asyncio.gather(
        uvicorn.Server(config_a).serve(),
        uvicorn.Server(config_b).serve(),
    )


if __name__ == "__main__":
    asyncio.run(main())
