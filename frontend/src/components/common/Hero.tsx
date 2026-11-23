import { type ReactNode } from "react";

const heroIcons: Record<string, string> = {
  dashboard: "f45f8.svg",
  logs: "16ea2.svg",
  sandbox: "78fb2.svg",
  keys: "2d536.svg",
  sources: "1b345.svg",
  settings: "e2164.svg",
};

export interface HeroProps {
  route: string;
  title: string;
  description: string;
  status?: ReactNode;
  actions?: ReactNode;
  icon?: string;
}

/**
 * Reusable Command Center Page Hero Header Component
 * Encapsulates breadcrumb route tracking, brand icon attribution, status pill, and action CTA slots.
 */
export function Hero({
  route,
  title,
  description,
  status,
  actions,
  icon,
}: HeroProps) {
  const iconKey = route.replace("/", "");
  const assetName = icon || heroIcons[iconKey] || "f45f8.svg";

  return (
    <header className="border-b border-[#c6c8bb] bg-white px-5 pb-6 pt-6 sm:px-8 shadow-xs">
      <div className="mx-auto max-w-[1280px]">
        <div className="font-mono-medium mb-4 flex flex-wrap items-center justify-between gap-2 text-xs leading-4">
          <div className="flex items-center gap-1.5 text-[#45483e]">
            <span>COMMAND CENTER</span>
            <span className="text-[#c6c8bb]">/</span>
            <span className="text-[#590907] font-semibold">{route}</span>
          </div>
          {status}
        </div>
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex items-center gap-4">
            <span className="grid size-11 shrink-0 place-items-center rounded-lg border border-[#c6c8bb] bg-[#e8d2b5] shadow-xs">
              <img
                src={`/assets/${assetName}`}
                alt=""
                className="size-[22px]"
                onError={(e) => {
                  (e.currentTarget as HTMLElement).style.display = "none";
                }}
              />
            </span>
            <div>
              <h1 className="font-heading-semibold text-[28px] leading-[34px] tracking-[-.25px] text-[#1a1d15]">
                {title}
              </h1>
              <p className="text-sm leading-5 text-[#45483e]">{description}</p>
            </div>
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      </div>
    </header>
  );
}
