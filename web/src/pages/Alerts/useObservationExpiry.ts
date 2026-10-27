import { useEffect, useState } from "react";

/** A receipt belongs to its original snapshot. Wall-clock changes never renew
 * its display lifetime; missing or already-old evidence has no fresh deadline. */
export function observationDeadline(
  age: string | null,
  received: number | null,
  maximum: number,
): number | null {
  if (
    age === null ||
    received === null ||
    !Number.isFinite(received) ||
    BigInt(age) > BigInt(maximum)
  )
    return null;
  return received + maximum - Number(age);
}

/** One panel timer only changes presentation. Callers select the earliest
 * still-fresh deadline and retain responsibility for network/session ownership. */
export function useObservationExpiry(
  deadline: number | null,
  enabled: boolean,
): void {
  const [, render] = useState(0);
  useEffect(() => {
    if (!enabled || deadline === null) return;
    // If the deadline passed between render and effect, still refresh once.
    // Inclusive validity ends immediately after the deadline, not at receipt.
    const timer = setTimeout(
      () => render((value) => value + 1),
      Math.max(1, Math.ceil(deadline - performance.now()) + 1),
    );
    return () => clearTimeout(timer);
  }, [deadline, enabled]);
}
