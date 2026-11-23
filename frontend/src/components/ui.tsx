import {
  useEffect,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { LoaderCircle, X, AlertTriangle, CheckCircle, Info } from "lucide-react";

export function Button({
  children,
  className = "",
  variant = "primary",
  loading,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  loading?: boolean;
}) {
  const styles = {
    primary:
      "border border-[#590907] bg-gradient-to-r from-[#590907] to-[#812720] text-white shadow-none hover:opacity-95",
    secondary:
      "border border-[#c6c8bb] bg-white text-[#1a1d15] hover:bg-[#f6efe5]",
    ghost:
      "text-[#45483e] hover:bg-[#efe6da] hover:text-[#1a1d15]",
    danger:
      "border border-[#93000a]/30 bg-[#ffdad5] text-[#93000a] hover:bg-[#ffc9c3]",
  };

  return (
    <button
      {...props}
      disabled={loading || props.disabled}
      className={`soft-press inline-flex h-10 items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold transition duration-150 disabled:cursor-not-allowed disabled:opacity-50 cursor-pointer ${styles[variant]} ${className}`}
    >
      {loading && <LoaderCircle className="size-4 animate-spin shrink-0" />}
      {children}
    </button>
  );
}

export function Input({
  label,
  hint,
  error,
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement> & {
  label?: string;
  hint?: ReactNode;
  error?: string;
}) {
  return (
    <label className="block space-y-1.5">
      {label && <span className="font-ui-medium text-xs text-[#45483e] block">{label}</span>}
      <input
        {...props}
        className={`h-11 w-full rounded-md border ${
          error ? "border-[#93000a] bg-[#ffdad5]/20" : "border-[#c6c8bb] bg-[#f6efe5]"
        } px-3.5 text-sm text-[#1a1d15] outline-none transition placeholder:text-[#76786d] focus:border-[#590907] focus:bg-white focus:ring-2 focus:ring-[#590907]/10 ${className}`}
      />
      {error && <span className="block text-xs text-[#93000a]">{error}</span>}
      {hint && !error && <span className="block text-xs text-[#76786d]">{hint}</span>}
    </label>
  );
}

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`ui-card rounded-lg border border-[#c6c8bb] bg-white ${className}`}>
      {children}
    </div>
  );
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "green" | "amber" | "red" | "violet" | "cyan" | "sage";
}) {
  const styles = {
    neutral: "border-[#c6c8bb] bg-[#f6efe5] text-[#45483e]",
    green: "border-[#1b5e3a]/20 bg-[#d8efe0] text-[#0b331e]",
    amber: "border-[#855300]/20 bg-[#f6dfc2] text-[#5a3800]",
    red: "border-[#93000a]/20 bg-[#ffdad5] text-[#7a0008]",
    violet: "border-[#590907]/20 bg-[#efe6da] text-[#590907]",
    cyan: "border-[#45483e]/20 bg-[#e2e4d6] text-[#34372f]",
    sage: "border-[#76786d]/20 bg-[#e2e4d6] text-[#34372f]",
  };

  return (
    <span
      className={`font-ui-medium inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium tracking-wide ${styles[tone]}`}
    >
      {children}
    </span>
  );
}

export function Modal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", handleKey);
      document.body.style.overflow = originalOverflow;
    };
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 animate-overlay-in grid place-items-center bg-[#1a1d15]/35 p-4 backdrop-blur-sm"
      onMouseDown={onClose}
    >
      <div
        className="animate-dialog-in w-full max-w-lg rounded-xl border border-[#c6c8bb] bg-white p-6 shadow-xl"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="mb-5 flex items-center justify-between">
          <h2 className="font-heading-semibold text-lg text-[#1a1d15]">{title}</h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded-md p-1.5 text-[#76786d] hover:bg-[#f6efe5] hover:text-[#1a1d15] cursor-pointer"
          >
            <X className="size-4" />
          </button>
        </div>
        {children}
      </div>
    </div>,
    document.body
  );
}

export function Dialog({
  open,
  onClose,
  icon,
  iconTone = "cream",
  title,
  subtitle,
  danger,
  maxWidth = 480,
  children,
}: {
  open: boolean;
  onClose: () => void;
  icon?: string;
  iconTone?: "cream" | "green" | "red";
  title: string;
  subtitle?: ReactNode;
  danger?: boolean;
  maxWidth?: number;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = originalOverflow;
    };
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  const iconBox = {
    cream: "border border-[#c6c8bb] bg-[#e8d2b5]",
    green: "bg-[#d8efe0]",
    red: "bg-[#ffdad5]",
  }[iconTone];

  return createPortal(
    <div
      className="fixed inset-0 z-50 animate-overlay-in grid place-items-center overflow-y-auto bg-[#1a1d15]/40 p-4 backdrop-blur-[2px]"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        style={{ maxWidth }}
        className="animate-dialog-in flex w-full flex-col gap-4 rounded-xl border border-[#c6c8bb] bg-white p-6 shadow-[0_24px_60px_-28px_rgba(26,29,21,.45)]"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            {icon ? (
              <span className={`grid size-10 shrink-0 place-items-center rounded-lg ${iconBox}`}>
                <img src={`/assets/${icon}`} alt="" className="size-5" />
              </span>
            ) : (
              <span className={`grid size-10 shrink-0 place-items-center rounded-lg ${iconBox}`}>
                <Info className="size-5 text-[#590907]" />
              </span>
            )}
            <div className="min-w-0">
              <h2
                className={`font-heading-semibold text-lg leading-6 ${
                  danger ? "text-[#93000a]" : "text-[#1a1d15]"
                }`}
              >
                {title}
              </h2>
              {subtitle && (
                <p className="font-mono-medium truncate text-xs leading-4 text-[#45483e]">
                  {subtitle}
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            aria-label="Close dialog"
            onClick={onClose}
            className="grid size-8 shrink-0 place-items-center rounded-lg hover:bg-[#f6efe5] text-[#76786d] hover:text-[#1a1d15] cursor-pointer"
          >
            <X className="size-4" />
          </button>
        </div>
        {children}
      </div>
    </div>,
    document.body
  );
}

export function DialogFooter({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[#c6c8bb] pt-4 mt-2">
      {children}
    </div>
  );
}

export function DialogButton({
  children,
  variant = "secondary",
  icon,
  loading,
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "secondary" | "primary" | "danger";
  icon?: string;
  loading?: boolean;
}) {
  const styles = {
    secondary:
      "border border-[#c6c8bb] bg-white px-4 py-2 text-[#1a1d15] hover:bg-[#f6efe5]",
    primary:
      "bg-gradient-to-r from-[#590907] to-[#812720] px-5 py-2 text-white hover:opacity-95 shadow-none",
    danger:
      "bg-[#93000a] px-5 py-2 text-white hover:bg-[#7a0008]",
  };

  return (
    <button
      {...props}
      disabled={loading || props.disabled}
      className={`soft-press font-ui-medium inline-flex items-center justify-center gap-1.5 rounded-lg text-sm leading-5 transition disabled:cursor-not-allowed disabled:opacity-60 cursor-pointer ${styles[variant]} ${className}`}
    >
      {loading ? (
        <LoaderCircle className="size-4 animate-spin" />
      ) : (
        icon && <img src={`/assets/${icon}`} alt="" className="size-4" />
      )}
      {children}
    </button>
  );
}

export function DialogField({
  label,
  side,
  children,
}: {
  label: string;
  side?: ReactNode;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="flex items-center justify-between">
        <span className="font-ui-medium text-xs leading-4 text-[#45483e]">{label}</span>
        {side}
      </span>
      {children}
    </label>
  );
}

export const dialogInputClass =
  "w-full rounded-lg border border-[#c6c8bb] bg-[#f6efe5] px-3.5 py-2.5 text-sm leading-5 text-[#1a1d15] outline-none transition placeholder:text-[#76786d] focus:border-[#590907] focus:bg-white focus:ring-2 focus:ring-[#590907]/10";

export function DialogWarning({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-[#855300]/40 bg-[#f6dfc2] p-3">
      <span className="shrink-0 pt-0.5 text-[#855300]">
        <AlertTriangle className="size-4" />
      </span>
      <div className="text-sm leading-5 text-[#251a08]">{children}</div>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
      <div>
        <h1 className="font-heading-semibold text-[28px] leading-[34px] tracking-[-.25px] text-[#1a1d15]">
          {title}
        </h1>
        <p className="text-sm leading-5 text-[#45483e]">{description}</p>
      </div>
      {action}
    </div>
  );
}

export function Empty({
  text,
  action,
}: {
  text: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <p className="text-sm text-[#76786d]">{text}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function AlertBanner({
  tone = "info",
  children,
}: {
  tone?: "info" | "success" | "warning" | "error";
  children: ReactNode;
}) {
  const styles = {
    info: "border-[#c6c8bb] bg-[#f6efe5] text-[#1a1d15]",
    success: "border-[#1b5e3a]/30 bg-[#d8efe0] text-[#0b331e]",
    warning: "border-[#855300]/30 bg-[#f6dfc2] text-[#5a3800]",
    error: "border-[#93000a]/30 bg-[#ffdad5] text-[#7a0008]",
  };

  const icons = {
    info: <Info className="size-4 shrink-0" />,
    success: <CheckCircle className="size-4 shrink-0 text-[#1b5e3a]" />,
    warning: <AlertTriangle className="size-4 shrink-0 text-[#855300]" />,
    error: <AlertTriangle className="size-4 shrink-0 text-[#93000a]" />,
  };

  return (
    <div className={`flex items-start gap-2.5 rounded-lg border p-3.5 text-sm ${styles[tone]}`}>
      <span className="mt-0.5">{icons[tone]}</span>
      <div className="flex-1 leading-5">{children}</div>
    </div>
  );
}
