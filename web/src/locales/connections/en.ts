import type zh from "./zh";

export default {
  "connections.backToCredentials": "Back to credentials",
  "connections.settings": "Connection settings",
  "connections.preview": "Connection preview",
  "connections.previewHint": "Choose an endpoint to generate a connection.",
  "connections.copyPassword": "Copy password",
  "connections.proxyUrl": "Proxy URL",
  "connections.examplesPasswordHint":
    "These examples include the password. Keep them private. Generating code does not test the connection.",
  "connections.curlReadyHint":
    "Run in PowerShell 7 (curl.exe on Windows) or a POSIX terminal. The password may remain in shell history and be visible to local processes.",
  "connections.pythonReadyHint":
    "Dependency: {dependency}. Save this private script and run it with Python. Dependencies are not installed automatically.",
  "connections.stateChanged": "Proxy state readings differ. Refresh to check.",
  "connections.openService": "Open proxy service (leave this window)",
  "connections.rememberEndpoint":
    "This browser remembers valid connection addresses, ports and protocols, but not passwords.",
  "connections.rememberFailed":
    "This browser could not retain the connection settings. Save the address before closing.",
  "connections.open": "Proxy endpoints",
  "connections.editAddress": "Edit address",
  "connections.listenerProtocol": "Listener protocol (read only)",
  "connections.startupAddress": "Startup address",
  "connections.selectionMode": "Address source",
  "connections.mode.inherit": "Follow startup configuration",
  "connections.mode.custom": "Custom address",
  "connections.mode.hidden": "Do not publish",
  "connections.clientHost": "Client-facing host",
  "connections.clientHostHint":
    "Enter a DNS name, IPv4 or IPv6 address without a scheme, port, path or authentication details.",
  "connections.clientPort": "Client-facing port",
  "connections.hostRule":
    "Enter a valid DNS name or usable unicast IP, not a URL, wildcard bind address or IPv6 zone identifier.",
  "connections.portRule":
    "Use a decimal port from 1 to 65535 without leading zeroes.",
  "connections.metadataOnly": "Only the public address changes",
  "connections.metadataOnlyHint":
    "The address persists across restarts. Listeners, egress, certificates, routing, port forwarding and firewall rules stay unchanged. Saving does not test connectivity.",
  "connections.hiddenHint":
    "This stops generating links without stopping the proxy, disconnecting clients or invalidating distributed addresses.",
  "connections.addressPreview": "Address after saving",
  "connections.notPublished": "No address published",
  "connections.previewIncomplete": "Enter a valid host and port to preview",
  "connections.saveDeclaration": "Save endpoint",
  "connections.readLatest": "Read latest endpoints",
  "connections.metadataRevision": "Endpoint version",
  "connections.metadataSaved": "Endpoint saved",
  "connections.metadataTicketHint":
    "This task saves endpoint addresses without changing the proxy policy version.",
  "connections.endpointDetails": "Endpoint details",
  "connections.connectivityNotTested": "Connectivity not tested",
  "connections.endpointCapacity":
    "The override limit is reached. Review and clear old overrides before editing another endpoint.",
  "connections.declarationSaved": "Endpoint saved.",
  "connections.remoteSaved":
    "Endpoint saved. Read the latest endpoints to check the address.",
  "connections.declarationRejected":
    "Save rejected. Read the latest endpoints before editing again.",
  "connections.declarationQueued":
    "Task recorded. Check its result; do not save again.",
  "connections.checkDeclaration": "Check task",
  "connections.writeUnknown":
    "Save result unknown. Do not resubmit. Read the latest endpoints or check the existing task, then review the current state before explicitly starting a new edit. Closing does not confirm the old result.",
  "connections.beginNewDeclaration": "Start a new edit",
  "connections.newDeclarationNotice":
    "The previous save result is still unknown. A new edit uses the current endpoints without replaying the old request.",
  "connections.managementUnsupported":
    "Endpoints are read only. Upgrade this node's software or migrate its management database to edit them.",
  "connections.otherCommand":
    "This node has a pending or blocked task. Check it before editing endpoints.",
  "connections.metadataTicket": "Endpoint task",
  "connections.blockedTicket":
    "Task blocked. Keep its ID and contact an administrator. This screen can only check the result, not retry, replace the task or save again.",
  "connections.detached": "Old overrides",
  "connections.detachedHint":
    "These settings match no current listener and are not usable endpoints. They can only be cleared, not assigned to another listener.",
  "connections.clearDetached": "Clear old override",
  "connections.clearDetachedHint":
    "Clear this old setting? No listener is added, removed or restarted. A future matching listener will follow its startup configuration.",
  "connections.close": "Close",
  "connections.reading": "Reading this node's proxy endpoints…",
  "connections.endpointHint":
    "Clients connect through these endpoints. Management addresses, server IPs, listen addresses and egress IPs are not substitutes.",
  "connections.observedState": "Proxy state in this response",
  "connections.notTested": "Configuration only · connection not tested",
  "connections.policyObservationHint":
    "Policy and endpoint state are separate observations; refresh to read them again. Saved or applied policy does not prove client DNS, TLS, authentication, target connectivity or egress IP. Configuration can still be exported when the proxy is stopped.",
  "connections.running": "Proxy running in this process",
  "connections.stopped": "No managed proxy running",
  "connections.runningHint":
    "This is one process-state observation, not continuous health or proof of reachability, authentication or a target connection. Read the latest endpoints to update it.",
  "connections.bind": "Node listen address",
  "connections.publicAddress": "Declared client endpoint",
  "connections.unconfigured": "No client endpoint configured",
  "connections.noListeners":
    "No managed proxy listeners are configured. The management API alone provides no proxy endpoint.",
  "connections.configuredHint":
    "Configure domain certificates, port forwarding and firewall rules separately.",
  "connections.unconfiguredHint":
    "Ask an authorized administrator to fill in missing endpoints. Listen addresses and management ports are never used as a fallback.",
  "connections.withoutCredentials":
    "These links contain no username or password",
  "connections.credentialHint":
    "Open a user's connection configuration on this node to read a saved password and generate an authenticated link. Older credentials may have no saved password.",
  "connections.selectEndpoint": "Select proxy endpoint",
  "connections.endpointChanged":
    "The selected entry changed or is no longer available. Your address is retained; choose an entry again.",
  "connections.manual": "Enter an endpoint manually",
  "connections.advancedRouting": "Advanced routing…",
  "connections.advancedRoutingHint":
    "Use only when derived addresses are needed. Choose a rule explicitly; opening these choices does not select or change your route.",
  "connections.derivedRoute": "Derived routing rule",
  "connections.derivedValue": "Derivation identifier (without hyphens)",
  "connections.ttlValue": "Time bucket length (seconds)",
  "connections.exitValue": "Authorized exit",
  "connections.poolValue": "Authorized pool",
  "connections.advancedDevice": "Advanced TCP preset",
  "connections.deviceOperationConflict":
    "The selected TCP preset does not support this operation. Choose a compatible TCP operation or explicitly set the preset to unspecified; it is not cleared automatically.",
  "connections.reviewDevice": "Review TCP preset",
  "connections.observationDetails":
    "Policy versions and preset backend details",
  "connections.readNames": "Read resource names",
  "connections.resourcesLink": "View all IP resources (leaves this window)",
  "connections.nameNotRead": "Name not read",
  "connections.namesHint":
    "Reads the first 50 entries of each resource kind on demand; authorized IDs outside those pages remain selectable. Names, IPs, families and states identify resources, not health, reachability or actual egress. Generation still rechecks authorization.",
  "connections.namesFailed":
    "Names could not be read at the current policy version, so authorized IDs are still shown. Refresh authorization and try again; no other node's or older names are substituted.",
  "connections.unsupported":
    "This remote node does not support endpoint discovery. Check and upgrade the target; no local or other node's address is substituted. You can still enter a confirmed endpoint manually in the credential configuration.",
  "connections.copyAuthenticatedUrl": "Copy proxy URL",
  "connections.clipboardWarning":
    "Copied passwords can be read by clipboard history, sync or other apps. Use a trusted device and clear the clipboard afterward.",
  "connections.copied": "Copied",
  "connections.copyFailed":
    "Copy failed. Check the browser's clipboard permission and try again.",
  "connections.downloadAuthenticatedUrl": "Download proxy URL",
  "connections.downloadWarning":
    "The file contains a username and password in plain text. Save it in a private folder, away from shared or synced locations. Repeated downloads create more copies. This page cannot confirm the save location or file permissions.",
  "connections.downloadRequested":
    "Download requested. Check your browser to confirm the file was saved.",
  "connections.downloadFailed":
    "Download request failed. Check your browser settings and try again; you do not need to issue another credential.",
  "connections.masqueAuth":
    "MASQUE uses an HTTPS URI template. Configure authentication separately in a CONNECT-UDP client; credentials are not embedded in the template, and no quic:// link is generated.",
  "connections.exportUrl": "Export proxy URL",
  "connections.clientExamples": "Developer client examples",
  "connections.copyExample": "Copy example code",
  "connections.examplesHint":
    "These examples contain no password. Enter it in your own terminal when running them. The destination is fixed to https://example.com/; generating code does not test the connection.",
  "connections.examplesUnsupported":
    "These examples support HTTP/HTTPS CONNECT and SOCKS5 CONNECT only. Plain HTTP forwarding, SOCKS5 BIND, UDP ASSOCIATE and MASQUE need their corresponding client configuration.",
  "connections.curlHint":
    "Run in PowerShell 7 or a POSIX interactive terminal (use curl.exe on Windows), then enter the proxy password. The command line contains no password. SOCKS5 resolves the destination hostname at the proxy. Older PowerShell empty-argument handling is not supported by this example.",
  "connections.pythonHint":
    "Requires supported, patched Requests and urllib3 versions (dependency: {dependency}). Save as a script and run in a terminal that can hide password input. Dependencies are not installed automatically.",
  "connections.examplesTls":
    "The client must trust the HTTPS proxy certificate normally; the destination certificate is verified separately. Configure private CAs according to the client documentation. Do not disable TLS verification.",
  "connections.unencryptedProxy":
    "HTTP/SOCKS5 do not encrypt proxy authentication; destination HTTPS does not protect it. Use a trusted network or an HTTPS proxy.",
  "connections.diagnostic": "Test this connection on your computer",
  "connections.diagnosticHint":
    "Download the checked connection profile, then run vproxy locally. The browser does not connect to the proxy or run this command. The CLI uses the fixed destination https://example.com/ and produces real proxy traffic that may be metered.",
  "connections.diagnosticMetadata":
    "This JSON contains the endpoint, full username and routing extensions, but no password. Keep it in a trusted folder; it can identify your account and selected exit or pool.",
  "connections.downloadDiagnostic":
    "Download connection test profile (no password)",
  "connections.diagnosticExpired":
    "Regenerate the checked preview before downloading. This browser limits profile downloads to one minute after reading the metadata; it is not a server permission expiry or a connection test.",
  "connections.diagnosticRequested":
    "Profile download requested. Check the saved file; no connection test has run.",
  "connections.diagnosticFailed":
    "Profile download request failed. Check browser settings; do not issue or rotate a credential to retry this download.",
  "connections.diagnosticRun":
    "Use a trusted terminal in the folder containing the downloaded file. Run the command below and enter your existing proxy password at the hidden prompt. No password is included in the command or profile.",
  "connections.diagnosticCommand": "Local vproxy connection test command",
  "connections.diagnosticPlaintext":
    "This command explicitly allows plaintext proxy authentication with --allow-plaintext. Run it only if you accept that risk on a trusted network. Destination HTTPS does not encrypt the client-to-proxy password exchange.",
  "connections.diagnosticCa":
    'For an HTTPS proxy with a private CA, add --proxy-ca "./proxy-ca.pem" using its trusted public CA bundle. That CA is used only for the proxy TLS layer, not the destination. TLS verification stays enabled.',
  "connections.diagnosticDns":
    "SOCKS5 resolves the fixed destination name at the proxy. HTTP/HTTPS use CONNECT; this profile does not test HTTP forwarding, BIND, UDP ASSOCIATE or MASQUE.",
  "connections.diagnosticAutomation":
    "For automation, --password-stdin reads the existing password from redirected stdin. Do not put it in command arguments or environment variables. A downloaded profile is configuration, not proof that a test passed.",
  "connections.diagnosticUnsupported":
    "Local diagnostics support HTTP/HTTPS CONNECT and SOCKS5 CONNECT only. Choose one of those operations and regenerate the preview to download a profile.",
} satisfies Record<keyof typeof zh, string>;
