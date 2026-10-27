import { canonicalId, count, shape } from "../api/proxy";
import { counter, type WebhookView } from "../api/notifications";

/** Write-ahead assertions only. No URL, header, token, request body or automatic
 * replay is stored. The administrator must explicitly finish an unknown review. */
export interface WebhookNote {
  administratorId: string;
  nodeId: string;
  operationId: string;
  revision: string;
  action: "configure" | "retry";
  deliveryId: string | null;
  attempts: number | null;
}
export const webhookCodec = {
  key: (value: WebhookNote) => `${value.administratorId}:${value.nodeId}`,
  decode(value: unknown): WebhookNote | null {
    try {
      shape(value, [
        "administratorId",
        "nodeId",
        "operationId",
        "revision",
        "action",
        "deliveryId",
        "attempts",
      ]);
      if (
        !canonicalId(value.administratorId) ||
        !canonicalId(value.nodeId) ||
        !canonicalId(value.operationId) ||
        !counter(value.revision) ||
        (value.action === "configure"
          ? value.deliveryId !== null || value.attempts !== null
          : value.action !== "retry" ||
            !canonicalId(value.deliveryId) ||
            !count(value.attempts, 4_294_967_294, 1))
      )
        return null;
      return { ...value } as unknown as WebhookNote;
    } catch {
      return null;
    }
  },
};

/** A current receipt can prove admission, never receiver execution or human
 * review. A later configuration/replacement can leave the old result unknown. */
export function webhookResult(
  note: WebhookNote,
  value: WebhookView,
): "saved" | "admitted" | "unknown" {
  if (note.nodeId !== value.node_id) return "unknown";
  if (note.action === "configure")
    return value.operation_id === note.operationId &&
      BigInt(value.revision) === BigInt(note.revision) + 1n
      ? "saved"
      : "unknown";
  if (note.revision !== value.revision) return "unknown";
  if (
    value.last_accepted_delivery_id === note.deliveryId ||
    (value.pending?.id === note.deliveryId &&
      (value.pending.attempts > (note.attempts ?? Infinity) ||
        (value.pending.attempts === note.attempts &&
          value.pending.outcome === "ready")))
  )
    return "admitted";
  return "unknown";
}
