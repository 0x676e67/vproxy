export default {
  "setup.firstUse.title": "Get started",
  "setup.firstUse.listener": "2. Enable the proxy",
  "setup.firstUse.unread": "Status unconfirmed",
  "setup.firstUse.notTested": "Client connectivity has not been tested.",
  "setup.firstUse.users": "1. Users and credentials",
  "setup.firstUse.userHint":
    "Choose or create a user, then choose or create one of their credentials. Saved passwords can be read in Connection configuration; older credentials may have no saved copy.",
  "setup.firstUse.ownerUnknown":
    "Control ownership is unconfirmed. Refresh node status.",
  "setup.firstUse.delegated":
    "Another node controls this node. You can view it here; make changes on the controller.",
  "setup.firstUse.manageUsers": "Open local users",
  "setup.firstUse.endpoints": "3. Copy a proxy link",
  "setup.firstUse.endpointHint":
    "Under a user's Credentials, open Connection configuration, read or enter the password, then copy the link. New nodes use the host's default egress; IP resources are optional.",
  "setup.firstUse.endpointUnavailable":
    "Refresh node status before checking users and connection configuration.",
  "setup.title": "Connect a node",
  "setup.continue": "Setup and verification",
  "setup.prepare": "Prepare the child",
  "setup.enroll": "Enroll both identities",
  "setup.grant": "Grant control on the child",
  "setup.save": "Save the destination",
  "setup.verify": "Verify a control read",
  "setup.stepNavigation": "Choose a setup step",
  "setup.stepLabel": "{current}/{total} · {title}",
  "setup.addressDetails": "Addresses and node identity",
  "setup.progressHint":
    "Instructions only. Continuing does not enroll certificates or grant permission.",
  "setup.independent": "Each node keeps its own data, policy and runtime.",
  "setup.pkiRequired":
    "Use an API-only management build on the child, without web-ui. The guide shows local instructions; it does not execute commands, install software or change certificate trust.",
  "setup.controllerId": "This manager's stable node ID",
  "setup.adminOrigin": "Administrator HTTPS origin",
  "setup.adminOriginHint":
    "The address used to sign in to the browser interface. It is not the node control address or a proxy entrance.",
  "setup.nodeOriginHint":
    "The fixed HTTPS origin of the child's separate node listener. This manager must be able to reach it, and its DNS/IP must match the node certificate's SAN.",
  "setup.proxyAddressHint":
    "An optional advertised proxy host:port per listener, used for client connection recipes. It is neither an administrator origin nor a node control destination.",
  "setup.prepareHint":
    "Inspect the existing data directory and keep its identity, certificates and verified startup configuration. Do not initialize it again or replace its signing roots. Administrator HTTPS and node mTLS remain separate; proxy listeners are optional.",
  "setup.preparationMode": "Child installation",
  "setup.newChild": "New installation",
  "setup.existingChild": "Existing node",
  "setup.existingLocked":
    "This destination is registered or its save is unconfirmed. Inspect the existing child; do not create another identity.",
  "setup.offlineAuthority":
    "Use an existing setup authority whose node CA this manager already accepts.",
  "setup.newOutputs":
    "Use a new output directory under a parent you control. If a command fails or its result is unknown, inspect that output before taking another action. Do not overwrite it or replay the command automatically.",
  "setup.offlinePrepare": "1. Prepare on the child",
  "setup.offlinePrepareHint":
    "Obtain the existing authority's public.json and verify its SHA-256 through a trusted channel. The terminal asks for a name, administrator and hidden password. Send only the child's generated public.json to the signing machine; its keys and state stay on the child.",
  "setup.offlineSign": "2. Sign on the signing machine",
  "setup.offlineSignHint":
    "Confirm the request's node ID and both HTTPS origins before signing. Return only the signed response directory to the original child. Both CA private keys stay on the signing machine. A signature does not enroll a peer or grant control.",
  "setup.offlinePlan": "3. Check and start on the child",
  "setup.offlinePlanHint":
    "Set both bind addresses explicitly for the intended access. A loopback bind is reachable only locally. Create the plan on the original child and keep its files at their original paths. Plan creation and checks do not open listeners or verify network access.",
  "setup.startHint":
    "After check succeeds, run one script for your operating system. Keep the API-only node running for the enrollment probes. The script rechecks its inputs; it does not grant trust, change firewall rules or authorize this manager.",
  "setup.startPosix": "Start on Linux / POSIX",
  "setup.startWindows": "Start with PowerShell",
  "setup.offlinePathsHint":
    "For this new installation, use these child paths in the enrollment and probe templates. Copy only public certificates to the other node; never transfer the private key or state directory.",
  "setup.childStatePath": "Child data directory",
  "setup.childCertificatePath": "Child public node certificate",
  "setup.childKeyPath": "Child private node key (stays local)",
  "setup.childCaPath": "Public node CA certificate",
  "setup.optionalProxy": "Optional: configure proxy listeners",
  "setup.optionalProxyHint":
    "The terminal guide creates a configuration without starting listeners. Encrypted proxies require existing certificate files. Check the new proxy launch plan, then use NEW_PROXY_LAUNCH_DIR for startup or service generation instead of the earlier management-only plan.",
  "setup.optionalService": "Optional: generate a Linux service file",
  "setup.optionalServiceHint":
    "Use the launch plan you intend to run. These commands only generate and check a user service file; they do not install, enable or start it. Review the reported unit and arrange installation separately.",
  "setup.commands": "Command templates and details",
  "setup.placeholderHint":
    "Reference templates only; nothing executes here. Choose the startup script labeled for your operating system and replace every <...> placeholder with your verified local value. Paths are not deployment defaults. Never paste a private key, CA signing key, password or proxy credential into this interface.",
  "setup.enrollHint":
    "Exchange public certificates and stable node IDs through a trusted channel.",
  "setup.privateKeysStayLocal":
    "Keep each node's private key on that node. A CA signature alone does not grant control. Register the exact peer leaf and its expected SAN on both nodes.",
  "setup.registrationHint":
    "Run the first registration on this manager and the second on the child. These templates are for new registrations; existing peers require their current authorization_revision with --expected-revision. Do not replace or re-enable a peer just to make a probe pass.",
  "setup.probeHint":
    "With both separately configured node listeners running, run a probe from each node toward the other. Confirm both reported node IDs through the trusted channel. A successful identity probe still does not grant policy control.",
  "setup.offlineGrant":
    "The child's local operator must grant control explicitly.",
  "setup.stopHint":
    "First arrange a maintenance window and stop that child's manage serve yourself. The offline command refuses a running instance; it never stops a service. Stopping a managed instance also stops its managed proxy listeners.",
  "setup.epochHint":
    "Requires schema 13 and the owner CLI. After stopping the child, read owner status and use its actual current epoch in grant. Never guess 1 or reuse an old epoch. This manager must already be an active enrolled non-self peer on the child. Even granting the same owner advances the epoch.",
  "setup.restartHint":
    "Check owner status again for this manager's exact node ID, then restart the child's existing, verified serve configuration. This guide cannot grant trust on the child's behalf or restart it. If a command's outcome is uncertain, inspect status before deciding any next action; do not automatically replay it.",
  "setup.close": "Close guide",
  "setup.previous": "Previous step",
  "setup.next": "Continue",
  "setup.saveAction": "Save destination once",
  "setup.saved": "Destination registered · control not yet verified",
  "setup.savedHint":
    "Saving only changes this manager's registry. It does not prove enrollment, ownership, reachability, proxy availability or egress health. A lost response may still follow a committed save.",
  "setup.saveUncertain":
    "The save was not confirmed and may have committed. Do not submit it again here. Close this guide, refresh the registry and inspect the exact node ID before deciding what to do next.",
  "setup.recoverRegistry": "Close and refresh the node registry",
  "setup.verifyAction": "Read and verify control permission",
  "setup.verified": "This control read was verified",
  "setup.verifiedHint":
    "The selected registered node and this manager's controller ID matched the verified policy response. This is a one-time observation, not continuous authorization, a proxy test or an IP health check. Ownership can change afterwards.",
  "setup.runtimeObserved": "Proxy runtime reported running · not health-tested",
  "setup.changed":
    "The node ID or destination configuration changed. Refresh the registry and open the intended node again.",
  "setup.inactive":
    "This destination is paused, retired or blocked by rollback detection. Resolve its state explicitly in the node registry before verification.",
  "setup.ownerMismatch":
    "The verified child policy does not name this manager as its controller. No control success is claimed.",
  "setup.troubleshoot": "What to check if verification fails",
  "setup.failureHint":
    "Check the fixed node origin, both exact certificate registrations and revisions, CA trust, certificate validity/SAN and dual serverAuth/clientAuth usages, the child's owner status, and software/schema compatibility. An authorization error alone does not identify which side is misconfigured. Do not disable TLS checks, automatically trust a new certificate or replay a mutation to diagnose it.",
};
