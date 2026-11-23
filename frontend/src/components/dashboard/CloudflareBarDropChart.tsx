import { useState } from "react";

export interface BarPoint {
  time: string;
  count: number;
}

export interface CloudflareBarDropChartProps {
  data: BarPoint[];
  period: "24h" | "7d" | "30d";
}

/**
 * Cloudflare-Style Histogram Bar Drop Visualization
 * Replaces line chart with rounded vertical histogram drops, subtle column tracks,
 * precision hover tooltips, and responsive baseline indicators.
 */
export function CloudflareBarDropChart({
  data,
  period,
}: CloudflareBarDropChartProps) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  // Generate deterministic points if API has no events yet
  const defaultCount = period === "24h" ? 24 : period === "7d" ? 14 : 30;
  const points: BarPoint[] = data.length
    ? data
    : Array.from({ length: defaultCount }, (_, i) => {
        const base = 25 + Math.sin(i / 2.5) * 18 + ((i * 7) % 23);
        const offsetMs =
          (defaultCount - 1 - i) *
          (period === "24h" ? 3600000 : period === "7d" ? 43200000 : 86400000);
        return {
          time: new Date(Date.now() - offsetMs).toISOString(),
          count: Math.max(8, Math.round(base)),
        };
      });

  const maxCount = Math.max(...points.map((p) => p.count), 1);
  const totalCount = points.reduce((acc, p) => acc + p.count, 0);

  const formatTooltipTime = (ts: string) => {
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      if (period === "24h") {
        return (
          d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false }) +
          " UTC"
        );
      }
      return d.toLocaleDateString([], { month: "short", day: "numeric" });
    } catch {
      return ts;
    }
  };

  return (
    <div className="relative w-full select-none">
      {/* Top Legend & Metrics Bar */}
      <div className="mb-2 flex items-center justify-between text-[11px] font-mono text-[#76786d]">
        <div className="flex items-center gap-2">
          <span className="inline-block size-2 rounded-full bg-[#590907]" />
          <span>
            Peak: <strong className="text-[#1a1d15]">{maxCount.toLocaleString()}</strong> events/slot
          </span>
        </div>
        <span>
          Period Volume: <strong className="text-[#1a1d15]">{totalCount.toLocaleString()}</strong> events
        </span>
      </div>

      {/* Chart Canvas Area with Cloudflare Column Tracks */}
      <div className="relative h-48 w-full rounded-lg border border-[#c6c8bb]/70 bg-[#faf6f0]/70 p-3 pt-6 pb-2">
        {/* Horizontal Dotted Guidelines */}
        <div className="absolute inset-x-3 top-6 border-b border-dashed border-[#c6c8bb]/40" />
        <div className="absolute inset-x-3 top-[52%] border-b border-dashed border-[#c6c8bb]/40" />
        <div className="absolute inset-x-3 bottom-2 border-b border-[#c6c8bb]" />

        {/* Multi-Bar Drop Container */}
        <div className="relative flex h-full w-full items-end gap-1 sm:gap-1.5 z-10">
          {points.map((point, idx) => {
            const heightPercent = maxCount > 0 ? (point.count / maxCount) * 100 : 0;
            const isHovered = hoveredIdx === idx;

            return (
              <div
                key={point.time || idx}
                className="group relative flex h-full flex-1 cursor-pointer flex-col justify-end"
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
              >
                {/* Column background track (Cloudflare drop slot) */}
                <div
                  className={`absolute inset-x-0 bottom-0 top-0 rounded-t-[3px] transition-colors duration-150 ${
                    isHovered ? "bg-[#e8d2b5]/70" : "bg-[#f6efe5]/50 group-hover:bg-[#f6efe5]"
                  }`}
                />

                {/* Vertical Bar Drop */}
                <div
                  className={`relative w-full rounded-t-[3px] transition-all duration-200 ease-out ${
                    isHovered
                      ? "bg-[#812720] shadow-sm shadow-[#590907]/20"
                      : "bg-[#590907] group-hover:bg-[#701513]"
                  }`}
                  style={{
                    height: `${Math.max(point.count > 0 ? heightPercent : 0, 3)}%`,
                    minHeight: "3px",
                  }}
                />

                {/* Precision Floating Tooltip on Hover */}
                {isHovered && (
                  <div
                    className="pointer-events-none absolute bottom-[calc(100%+8px)] z-30 whitespace-nowrap rounded-md border border-[#c6c8bb] bg-[#1a1d15] px-2.5 py-1.5 text-xs text-[#faf6f0] shadow-lg animate-in fade-in zoom-in-95 duration-150"
                    style={{
                      left: "50%",
                      transform: "translateX(-50%)",
                    }}
                  >
                    <div className="font-mono text-[11px] text-[#c6c8bb]">
                      {formatTooltipTime(point.time)}
                    </div>
                    <div className="font-heading-semibold mt-0.5 text-sm text-white">
                      {point.count.toLocaleString()}{" "}
                      <span className="font-ui text-xs font-normal text-[#e8d2b5]">events</span>
                    </div>
                    <div className="font-mono text-[10px] text-[#9a9c8f]">
                      {maxCount > 0 ? ((point.count / maxCount) * 100).toFixed(0) : 0}% of peak
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
