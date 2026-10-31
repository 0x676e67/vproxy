import type zhCN from "./zh-CN";
import users from "./users/en";
import control from "./control/en";
import resources from "./resources/en";
import traffic from "./traffic/en";
import presets from "./presets/en";
import connections from "./connections/en";
import setup from "./setup/en";
import alerts from "./alerts/en";
import certificates from "./certificates/en";
import maintenance from "./maintenance/en";
import runtime from "./runtime/en";
import commandHistory from "./commandHistory/en";
import alertEvents from "./alertEvents/en";
import notifications from "./notifications/en";
import service from "./service/en";

export default {
  "theme.title": "Theme",
  "theme.current": "Current theme",
  "theme.light": "Light",
  "theme.dark": "Dark",
  "layout.expandNavigation": "Expand sidebar",
  "layout.collapseNavigation": "Collapse sidebar",
  "layout.openNavigation": "Open navigation",
  "layout.closeNavigation": "Close navigation",
  "control.registeredNodes": "Registered nodes",
  "control.registrationHelp": "Node registration help",
  ...service,
  ...users,
  ...control,
  ...resources,
  ...traffic,
  ...presets,
  ...connections,
  ...setup,
  ...alerts,
  ...certificates,
  ...maintenance,
  ...runtime,
  ...commandHistory,
  ...alertEvents,
  ...notifications,
  "menu.nodes": "Nodes",
  "app.language": "Interface language",
  "app.tools": "Tools",
  "app.projectRepository": "GitHub repository",
  "app.pageUnavailable": "This page could not be displayed",
  "app.pageReloadNotice":
    "Submitted operations may still be running. Reload the page and check their results before submitting again.",
  "app.reloadPage": "Reload page",
  "app.sample": "Local samples",
  "app.sampleNotice": "Frontend demo — no backend or real nodes connected.",
  "app.sampleDescription":
    "Metrics, health and configuration are synthetic. Added samples stay on this page until reload; no enrollment or configuration is sent.",
  "auth.description": "Sign in to local node management",
  "auth.username": "Administrator username",
  "auth.password": "Administrator password",
  "auth.usernameRequired": "Enter the administrator username",
  "auth.passwordRequired": "Enter the administrator password",
  "auth.passwordLength": "Use at most 1024 UTF-8 bytes for the password",
  "auth.credentialsNotice":
    "Use administrator credentials created by manage init. Proxy-user credentials cannot sign in here.",
  "auth.signIn": "Sign in",
  "auth.accountMenu": "Account menu: {username}",
  "auth.signOut": "Sign out",
  "account.password.title": "Change password",
  "account.password.submit": "Change and sign out",
  "account.password.cancel": "Cancel",
  "account.password.scope":
    "Change the local administrator password for {username}. This does not change a remote node or proxy-user credential.",
  "account.password.sessions":
    "All browser sessions for this administrator will be signed out. Other administrators stay signed in.",
  "account.password.current": "Current password",
  "account.password.next": "New password",
  "account.password.confirmation": "Confirm new password",
  "account.password.currentRequired":
    "Enter the current password (at most 1024 UTF-8 bytes, no control characters).",
  "account.password.policy":
    "Use at least 12 characters and at most 1024 UTF-8 bytes, without control characters. Spaces are preserved.",
  "account.password.mismatch": "The new passwords do not match.",
  "account.password.incorrect":
    "The current password is incorrect. No password change was made.",
  "account.password.changed":
    "Password changed. Sign in again with your new password.",
  "account.password.unconfirmed":
    "The password-change result is unconfirmed. Do not submit it again automatically. Try signing in with the new password; if access stays blocked, ask the operator to verify or recover the account.",
  "account.password.blocked":
    "The server could not confirm the password-change commit and has blocked new sign-ins. Ask the operator to restart management, then verify the new password. Do not repeat the change automatically.",
  "account.password.failed":
    "Your former sessions cannot be used. Sign in again before doing anything else; do not repeat the password change automatically.",
  "auth.refreshSession": "Refresh session",
  "auth.checking": "Checking the management session…",
  "auth.unavailable": "Cannot verify the management session",
  "auth.httpsTitle": "Open the HTTPS management address",
  "auth.httpsRequired":
    "Open the interface over HTTPS on the same origin as the management API. HTTP development previews do not send management credentials.",
  "auth.invalidCredentials": "Incorrect username or password",
  "auth.rateLimited": "Too many login attempts. Wait a minute and try again.",
  "auth.busy": "Authentication is temporarily busy. Please try again shortly.",
  "auth.logoutUnconfirmed":
    "Sign-out could not be confirmed. Your session may still be active; please retry signing out.",
  "api.network":
    "Cannot connect to the management API. Check the same-origin HTTPS service and try again.",
  "api.format":
    "The management API returned an unexpected response. Check frontend/backend versions and same-origin deployment.",
  "api.server":
    "The management request did not complete. Please try again shortly.",
  "api.origin":
    "The request origin does not match the management API configuration. Check the interface's HTTPS address.",
  "api.csrf": "Request verification failed. Refresh the session and try again.",
  "api.retry": "Retry",
  "nodes.title": "Node management",
  "nodes.description":
    "Monitor control links, egress health and configuration. Nodes run independently: a disconnected control link does not mean the proxy stopped.",
  "nodes.overview": "Node overview",
  "nodes.refresh": "Refresh node",
  "nodes.loading": "Reading the local node identity…",
  "nodes.loadFailed": "Cannot read node information",
  "nodes.liveNotice": "Identity read from the local management API",
  "nodes.liveSummary":
    "View the local identity and administrator API session. Capabilities not yet connected remain unknown.",
  "nodes.apiReadSuccessCount": "Last admin API request succeeded",
  "nodes.liveDescription":
    "Only the local identity is available. Proxy state, IP health, metrics, management relationships and configuration remain unknown until their APIs are implemented.",
  "nodes.health": "IP health",
  "nodes.configuration": "Configuration",
  "nodes.search": "Search nodes, regions or parents",
  "nodes.clearSearch": "Clear node search",
  "nodes.filter": "Filter by node status",
  "nodes.all": "All",
  "nodes.attention": "Needs attention",
  "nodes.disconnectedFilter": "Control disconnected",
  "nodes.count": "{count, plural, one {# node} other {# nodes}}",
  "nodes.registered": "Registered nodes",
  "nodes.connectedCount": "Control connected",
  "nodes.attentionCount": "Needs attention",
  "nodes.connectionsTotal": "Observed active connections",
  "nodes.observedOnly":
    "Only nodes with observations are included. No observations means unknown, not zero.",
  "nodes.empty": "No matching nodes",
  "nodes.emptyHint": "Try another name, region or status filter.",
  "node.name": "Node name",
  "node.id": "Node ID",
  "node.version": "Software version",
  "node.platform": "OS and architecture",
  "node.relationshipUnknown": "Management relationships unknown",
  "node.adminApi": "Administrator API",
  "node.apiReadSuccess": "Last admin API request succeeded",
  "node.region": "Region",
  "node.zone": "Zone",
  "node.local": "Local",
  "node.independent": "Independent",
  "node.managed": "Managed",
  "node.manages": "Manages {count, plural, one {# child} other {# children}}",
  "node.proxyRole": "Proxy",
  "node.parent": "Parent",
  "node.plannedParent": "Proposed parent",
  "node.noParent": "No parent",
  "node.control": "Control link",
  "node.connected": "Connected",
  "node.disconnected": "Disconnected",
  "node.pending": "Pending enrollment",
  "node.proxy": "Proxy status",
  "node.running": "Running",
  "node.unknown": "Unknown",
  "node.connections": "Active connections",
  "node.upload": "Upload",
  "node.download": "Download",
  "node.cpu": "CPU",
  "node.memory": "Memory",
  "node.details": "Details",
  "node.detailsLabel": "View details for {name}",
  "node.healthLabel": "View IP health for {name}",
  "node.configLabel": "View configuration for {name}",
  "node.observed": "State observed: {age}",
  "node.lastObservation": "Last state observation",
  "node.noObservation": "No state observation yet",
  "node.staleNote":
    "Control link disconnected. Proxy state and current health are unknown; this does not establish that the proxy stopped.",
  "node.pendingNote":
    "Local sample only. Not enrolled; no health checks have run.",
  "node.configNote":
    "Applied r{applied}, desired r{desired}. Awaiting acknowledgement.",
  "health.title": "Egress IP health",
  "health.description":
    "Only node-reported health is shown; missing observations remain unknown. IPv6 shows baseline and active-address coverage, not exhaustive prefix verification.",
  "health.ipv4": "IPv4 health",
  "health.healthy": "Healthy",
  "health.unhealthy": "Unhealthy",
  "health.unconfirmed": "Unconfirmed",
  "health.summary": "{healthy, number} / {total, number} healthy",
  "health.failures": "{count, plural, one {# unhealthy} other {# unhealthy}}",
  "health.unknownCount":
    "{count, plural, one {# unconfirmed} other {# unconfirmed}}",
  "health.stale": "Stale observation",
  "health.notChecked": "Not checked yet",
  "health.ipv6": "IPv6 prefix baseline",
  "health.prefixes": "{count, plural, one {# prefix} other {# prefixes}}",
  "health.activeAddresses":
    "{count, plural, one {# active address} other {# active addresses}}",
  "health.coverage":
    "Limited sentinels and active addresses, not a full prefix scan",
  "health.observed": "Health observed: {age}",
  "health.noObservation": "No health observation yet",
  "health.source": "Source address",
  "health.prefix": "IPv6 prefix",
  "health.lastObservation": "Last health observation",
  "config.description":
    "Revisions are node-scoped. Desired does not mean applied; this interface sends no configuration.",
  "config.applied": "Applied revision",
  "config.desired": "Desired revision",
  "config.state": "Configuration status",
  "config.synced": "Applied",
  "config.awaiting": "Awaiting application",
  "config.unconfirmed": "Acknowledgement unknown",
  "config.notEnrolled": "Not enrolled",
  "config.readOnly":
    "Sample revisions only. Saving, delivery and application are not implemented.",
  "config.unavailable":
    "The management API does not yet provide configuration or application acknowledgements. Revisions remain unknown; this interface does not modify configuration.",
  "health.unavailable": "Health observations are not connected; no probes run",
  "form.add": "Add sample node",
  "form.title": "Add a local sample node",
  "form.notice":
    "This is not node enrollment or remote control. Up to 20 samples can be created to explore the interface.",
  "form.namePlaceholder": "For example: au-edge-01",
  "form.regionPlaceholder": "For example: Sydney, Australia",
  "form.parentPlaceholder": "Optional; no parent means independent",
  "form.nameRequired": "Enter a node name",
  "form.namePattern":
    "Use 1–48 lowercase letters, digits or hyphens; start and end with a letter or digit",
  "form.nameDuplicate": "A node with this name already exists",
  "form.regionRequired": "Enter a region",
  "form.regionLength": "Use no more than 64 characters for the region",
  "form.limit": "Sample limit reached",
  "form.submit": "Create sample",
  "form.cancel": "Cancel",
  "form.added": "Local sample created; no real node connected",
  "region.hongKong": "Hong Kong",
  "region.tokyo": "Tokyo, Japan",
  "region.singapore": "Singapore",
  "region.losAngeles": "Los Angeles, US",
  "region.frankfurt": "Frankfurt, Germany",
  "region.osaka": "Osaka, Japan",
  "notFound.title": "Page not found",
  "notFound.description": "Open node management to continue.",
  "notFound.back": "Back to nodes",
} satisfies Record<keyof typeof zhCN, string>;
