import { type ReactNode } from "react";

export interface PageBodyProps {
  children: ReactNode;
  className?: string;
}

/** Standard responsive layout container for page views */
export function PageBody({ children, className = "" }: PageBodyProps) {
  return (
    <div className={`mx-auto flex max-w-[1280px] flex-col gap-6 p-4 sm:p-6 lg:p-8 ${className}`}>
      {children}
    </div>
  );
}
