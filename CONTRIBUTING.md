## Contributing

Issues and pull requests are welcome. Please feel free to open an issue to report bugs, propose improvements, or discuss design decisions before submitting larger changes.

If you’re looking for a place to start, the **Recommended contributions** section highlights areas where help would be especially valuable.

For research discussions or potential collaborations, you are also welcome to reach out via email at [sec@berkeley.edu](mailto:sec@berkeley.edu).


## Principles

- **Simplicity / Portability**: Single file (for main feature), ideally less than 1000 lines of code, no heavy dependencies.
- **Security-First**: Secure defaults, secret-backed authentication, and whitelist-based access control.
- **Neutrality / Standards-Driven**: Make only assumptions based on publicly available MCP specifications and standards; avoid vendor- or implementation-specific behavior.
- **Readable Over clever**： Optimize for maintainability and reviewability rather than performance black magic.

## Recommended contributions

- **Bearer and header-based authentication support** for configuring MCP servers.
    - This could be extended in the future to support additional authentication schemes such as API keys, OAuth 2.0, and others.
- **Per-client frontend UI** for quickly viewing reachable servers and testing accessible tools.
- **An authenticated admin configuration UI** with forms and draggable graphs (e.g., built with React Flow) for managing `config.toml` entries, including clients, servers, and access control.
    - This could also leverage JavaScript MCP libraries to demonstrate tool-list filtering in real time and provide a playground for testing configuration changes.
- **Improved logging and error handling**, with structured, Grafana/Loki-friendly output for per-client and per-server MCP call and result tracing.
    - This could later be extended to integrate with popular LLM and MCP observability and tracing tools.
- **Making config / secret root folder configurable** via command-line argument or environment variable, instead of hardcoding `./config` and `./secrets`.
- **Code cleaning / style improvements**. Existing code is partially AI-generated and could benefit from a human touch to improve readability, maintainability, and overall style.
