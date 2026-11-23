import { type ReactNode } from "react";

export interface SectionTitleProps {
  title: string;
  description?: string;
  side?: ReactNode;
}

/** Card section title header with optional description subtitle and side controls */
export function SectionTitle({ title, description, side }: SectionTitleProps) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="font-heading-semibold text-lg leading-6 text-[#1a1d15]">{title}</h2>
        {description && <p className="mt-0.5 text-sm leading-5 text-[#45483e]">{description}</p>}
      </div>
      {side}
    </div>
  );
}
