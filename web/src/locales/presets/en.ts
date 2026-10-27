import type zh from "./zh";
export default {
  "presets.title": "Connection presets",
  "presets.capability": "Read preset capability",
  "presets.editorTitle": "Connection presets · {name}",
  "presets.backend.ready": "Last read: complete preset backend available",
  "presets.backend.disabled": "Preset backend disabled",
  "presets.backend.unsupported": "Complete preset backend unsupported",
  "presets.backend.unavailable": "Preset backend unavailable",
  "presets.reason.not_configured":
    "No preset backend was configured at startup.",
  "presets.reason.feature_disabled":
    "This node was built without preset support.",
  "presets.reason.platform_unsupported":
    "This platform does not support the backend.",
  "presets.reason.proxy_unavailable":
    "This management process has no available proxy backend.",
  "presets.scopeHint":
    "Active TCP egress only; not MASQUE, SOCKS UDP or passive BIND. Built-in layouts do not select a real operating system or guarantee full device emulation.",
  "presets.snapshot":
    "Capability is read manually, not continuously. Management reachability does not establish continuous proxy or preset availability.",
  "presets.catalogRevision": "Built-in catalog version (not policy revision)",
  "presets.abi": "Backend ABI version",
  "presets.observed": "Node observation time",
  "presets.available": "Currently available presets",
  "presets.allowed": "Presets the client may select",
  "presets.default": "Default preset",
  "presets.native": "Host native (no user default)",
  "presets.inherit": "Inherit user default",
  "presets.defaultRule":
    "A non-empty user default must belong to the allowed set.",
  "presets.confirm": "Confirm connection preset update",
  "presets.newFlows":
    "Only subsequent active TCP egress is affected; established or reused connections are not renegotiated. Saving/loading a policy does not prove successful application to every target.",
  "presets.precedence":
    "Explicit device → selected pool default → user default → host native. The final preset still needs user authorization; conflicts or an unavailable backend are rejected, never silently downgraded.",
  "presets.unknown":
    "No verified policy has been read; no permissive defaults are used.",
  "presets.operationUnsupported":
    "This operation does not support an explicit TCP preset.",
  "presets.unavailable":
    "The preset backend is unavailable; the requested preset is not silently ignored.",
  "presets.generator": "Open connection",
  "presets.generatorTitle": "Connection configuration · {name}",
  "presets.endpointHint":
    "Choose this node's configured proxy entry point, or enter one manually. Management addresses and server IPs do not establish a usable proxy endpoint; a controller does not relay traffic automatically.",
  "presets.previewHint":
    "Generated from the policy snapshot just read. Real connections still undergo node authorization, resource-state and backend checks.",
  "presets.host": "Proxy host (without scheme or port)",
  "presets.port": "Proxy port",
  "presets.protocol": "Proxy protocol",
  "presets.operation": "Operation",
  "presets.http_forward": "HTTP request forwarding",
  "presets.http_connect": "HTTP CONNECT tunnel",
  "presets.socks5_connect": "SOCKS5 CONNECT",
  "presets.socks5_bind": "SOCKS5 passive BIND",
  "presets.socks5_udp": "SOCKS5 UDP ASSOCIATE",
  "presets.masque_udp": "MASQUE CONNECT-UDP",
  "presets.route": "Routing selection",
  "presets.noRoutes":
    "This user has no authorized routes. Configure routing permissions before generating a connection.",
  "presets.route.default": "Node default egress",
  "presets.route.exit": "Explicit exit",
  "presets.route.pool": "Explicit pool",
  "presets.route.session": "Session-derived routing",
  "presets.route.range": "Range-derived routing",
  "presets.route.ttl": "TTL time bucket",
  "presets.routeValue": "Identifier or seconds",
  "presets.device": "Explicit device (overrides defaults)",
  "presets.automatic": "Unspecified; resolve from policy",
  "presets.effective": "Expected TCP preset for this operation",
  "presets.generate": "Read authorization and generate",
  "presets.endpoint": "Unverified proxy endpoint",
  "presets.secretMemory":
    "An entered password is not uploaded or saved in browser storage. Password-bearing configurations leave this window only when you copy or download them. Closing clears the window's copy.",
  "presets.invalidInput":
    "Check the endpoint, port, permitted route and preset. Identifiers cannot contain hyphens; TTL must be a canonical non-zero integer.",
  "presets.unknownPolicy":
    "Capability or authorization could not be read, so no verified configuration can be generated. Local or sample data never replaces the selected node.",
} satisfies Record<keyof typeof zh, string>;
