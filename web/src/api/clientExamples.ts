import type { ConnectionOperation } from "./connection";
import {
  connectionUrl,
  validConnectionUsername,
  type EndpointProtocol,
} from "./endpoints";
import { ApiError } from "./error";
import { shape } from "./proxy";

/** Non-secret fields selected from a validated connection preview. The operation
 * remains explicit because a SOCKS5 URL alone cannot describe BIND or UDP. */
export interface ClientExampleInput {
  protocol: EndpointProtocol;
  host: string;
  port: number;
  username: string;
  operation: ConnectionOperation;
}
export type ClientExamples =
  | {
      supported: true;
      curl: string;
      python: string;
      pythonDependency: "requests" | "requests[socks]";
      httpsProxy: boolean;
      containsPassword: boolean;
    }
  | { supported: false; reason: "operation_unsupported" };

const operations: readonly ConnectionOperation[] = [
  "http_forward",
  "http_connect",
  "socks5_connect",
  "socks5_bind",
  "socks5_udp",
  "masque_udp",
];
const destination = "https://example.com/";

/** Generate client recipes from a checked connection. Without the optional
 * password they prompt privately; with it they are ready to run and sensitive.
 * Callers must keep authenticated recipes out of storage, URLs and telemetry.
 * Unknown metadata fields and invalid identifiers fail with ApiError("format").
 * Unsupported operations return no executable example.
 *
 * Both clients keep TLS verification enabled. Their installed CA trust and
 * supported, patched client versions remain operator prerequisites; emitting a
 * recipe is not proof of connectivity or of a particular client's TLS backend.
 * Username-only curl proxy authentication prompts in the tool, not the shell:
 * https://github.com/curl/curl/blob/curl-8_17_0/src/tool_paramhlp.c#L512-L558 */
export function clientExamples(
  input: ClientExampleInput,
  password?: string,
): ClientExamples {
  shape(input, ["protocol", "host", "port", "username", "operation"]);
  if (
    !validConnectionUsername(input.username) ||
    !operations.includes(input.operation)
  )
    throw new ApiError("format");
  const endpoint = connectionUrl({
    protocol: input.protocol,
    host: input.host,
    port: input.port,
  });
  if (!(
    ((input.protocol === "http" || input.protocol === "https") &&
      input.operation === "http_connect") ||
    (input.protocol === "socks5" && input.operation === "socks5_connect")
  ))
    return { supported: false, reason: "operation_unsupported" };
  if (password !== undefined) connectionUrl(input, input.username, password);

  // These clients use socks5h for proxy-side DNS; the general connection URL
  // deliberately retains socks5. Never rewrite the user's saved endpoint.
  const scheme = input.protocol === "socks5" ? "socks5h" : input.protocol;
  const authority = endpoint.slice(endpoint.indexOf("://") + 3);
  const proxy = `${scheme}://${authority}`;
  const username = JSON.stringify(input.username);
  const auth = input.protocol === "socks5" ? "--socks5-basic" : "--proxy-basic";
  const curl = [
    "curl --disable",
    `--proxy ${JSON.stringify(proxy)}`,
    `--proxy-user ${JSON.stringify(password === undefined ? input.username : `${input.username}:${password}`)}`,
    auth,
    '--noproxy ""',
    "--connect-timeout 10 --max-time 30",
    "--silent --show-error --head",
    JSON.stringify(destination),
  ].join(" ");
  const python = [
    "from getpass import GetPassWarning, getpass",
    "from urllib.parse import quote",
    "import warnings",
    "",
    "import requests",
    "",
    // getpass can otherwise fall back to echoed stdin outside a terminal.
    'warnings.simplefilter("error", GetPassWarning)',
    'password = ""',
    'proxy = ""',
    "try:",
    password === undefined
      ? '    password = getpass("Proxy password: ")'
      : `    password = ${JSON.stringify(password)}`,
    "    proxy = (",
    `        ${JSON.stringify(`${scheme}://`)}`,
    `        + quote(${username}, safe="")`,
    '        + ":" + quote(password, safe="")',
    `        + ${JSON.stringify(`@${authority}`)}`,
    "    )",
    "    with requests.Session() as session:",
    "        session.trust_env = False",
    "        with session.get(",
    `            ${JSON.stringify(destination)},`,
    '            proxies={"https": proxy},',
    "            timeout=(10, 20),",
    "            allow_redirects=False,",
    "            stream=True,",
    "            verify=True,",
    "        ) as response:",
    "            print(response.status_code)",
    "except (requests.RequestException, GetPassWarning, EOFError):",
    '    raise SystemExit("Proxy request failed; check endpoint, credentials and TLS trust.") from None',
    "except KeyboardInterrupt:",
    "    raise SystemExit(130) from None",
    "finally:",
    '    password = ""',
    '    proxy = ""',
  ].join("\n");
  return {
    supported: true,
    curl,
    python,
    pythonDependency:
      input.protocol === "socks5" ? "requests[socks]" : "requests",
    httpsProxy: input.protocol === "https",
    containsPassword: password !== undefined,
  };
}
