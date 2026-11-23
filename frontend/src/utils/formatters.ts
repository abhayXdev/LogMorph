/**
 * LogMorph Shared Utility Formatters & DOM Helpers
 * Clean, pure functions adhering to Single Responsibility Principle (SRP).
 */

/** Format ISO timestamp to human-readable locale string */
export function formatDate(date?: string | null): string {
  if (!date) return "Never";
  try {
    return new Intl.DateTimeFormat("en", {
      month: "short",
      day: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(date));
  } catch {
    return date;
  }
}

/** Map RFC 5424 severity level to UI Badge tone */
export function severityTone(
  severity: string
): "neutral" | "green" | "amber" | "red" | "violet" {
  const norm = (severity || "").toUpperCase();
  if (norm === "CRITICAL" || norm === "ERROR" || norm === "EMERGENCY" || norm === "ALERT") {
    return "red";
  }
  if (norm === "WARNING" || norm === "WARN") {
    return "amber";
  }
  if (norm === "INFO" || norm === "INFORMATIONAL" || norm === "NOTICE") {
    return "green";
  }
  return "neutral";
}

/** Serialize query parameter object into URL query string */
export function queryString(params: Record<string, string | number | undefined>): string {
  const output = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== "" && value !== undefined) output.set(key, String(value));
  });
  return output.toString();
}

/** Universal Enter-key auto-progression across form inputs */
export function handleFieldProgression(e: React.KeyboardEvent<HTMLFormElement>): void {
  if (e.key === "Enter") {
    const target = e.target as HTMLElement;
    if (target.tagName === "INPUT") {
      const form = target.closest("form");
      if (!form) return;
      const inputs = Array.from(
        form.querySelectorAll<HTMLInputElement>(
          'input:not([type="hidden"]):not([type="submit"]):not([disabled])'
        )
      );
      const idx = inputs.indexOf(target as HTMLInputElement);
      if (idx !== -1 && idx < inputs.length - 1) {
        e.preventDefault();
        inputs[idx + 1].focus();
      }
    }
  }
}

/** Safe clipboard helper ensuring callback triggers reliably */
export function copyToClipboard(text: string, onCopied?: () => void): void {
  try {
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
  } catch {
    // Safe fallback
  }
  if (onCopied) onCopied();
}
