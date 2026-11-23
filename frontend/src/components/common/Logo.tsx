import { Link } from "react-router";

export interface LogoProps {
  light?: boolean;
  className?: string;
}

/** Reusable brand logo and wordmark component */
export function Logo({ light = false, className = "" }: LogoProps) {
  return (
    <Link
      to="/"
      className={`flex items-center gap-2.5 transition hover:opacity-90 ${
        light ? "text-[#1a1d15]" : "text-[#1a1d15]"
      } ${className}`}
    >
      <span className="grid size-9 place-items-center rounded-lg bg-[#590907] shadow-xs">
        <img src="/assets/35073.svg" alt="LogMorph Logo" className="size-5" />
      </span>
      <span className="font-heading-semibold text-lg tracking-tight">LogMorph</span>
    </Link>
  );
}
