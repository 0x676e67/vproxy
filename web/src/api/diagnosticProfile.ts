import { connectionHost, type ConnectionOperation } from "./connection";
import {
  connectionUrl,
  validConnectionUsername,
  type EndpointProtocol,
} from "./endpoints";
import { ApiError } from "./error";
import { shape } from "./proxy";

export interface DiagnosticProfile {
  format_version: 1;
  protocol: "http" | "https" | "socks5";
  host: string;
  port: number;
  username: string;
  operation: "connect";
}
export interface DiagnosticInput {
  protocol: EndpointProtocol;
  host: string;
  port: number;
  username: string;
  operation: ConnectionOperation;
}
/** Build only public connection metadata. Unsupported operations produce no
 * profile, while malformed or secret-bearing inputs are rejected explicitly. */
export function diagnosticProfile(
  input: DiagnosticInput,
): Readonly<DiagnosticProfile> | null {
  shape(input, ["protocol", "host", "port", "username", "operation"]);
  if (
    !validConnectionUsername(input.username) ||
    ![
      "http_forward",
      "http_connect",
      "socks5_connect",
      "socks5_bind",
      "socks5_udp",
      "masque_udp",
    ].includes(input.operation)
  )
    throw new ApiError("format");
  connectionUrl({
    protocol: input.protocol,
    host: input.host,
    port: input.port,
  });
  if (!(
    ((input.protocol === "http" || input.protocol === "https") &&
      input.operation === "http_connect") ||
    (input.protocol === "socks5" && input.operation === "socks5_connect")
  ))
    return null;
  let host = connectionHost(input.host);
  if (host.includes(":")) {
    host = new URL(`http://[${host}]/`).hostname.slice(1, -1);
    // Rust's IpAddr Display uses dotted decimal for IPv4-mapped IPv6, while
    // WHATWG URL serializes the final 32 bits as two hexadecimal groups.
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (mapped) {
      const high = parseInt(mapped[1], 16),
        low = parseInt(mapped[2], 16);
      host = `::ffff:${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
    }
  }
  return Object.freeze({
    format_version: 1,
    protocol: input.protocol,
    host,
    port: input.port,
    username: input.username,
    operation: "connect",
  });
}
