import { useState } from "react";
import { ChevronRight } from "lucide-react";

function Node({
  name,
  value,
  depth = 0,
}: {
  name?: string;
  value: unknown;
  depth?: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const isObject = value !== null && typeof value === "object";

  if (!isObject) {
    let colorClass = "text-[#6c5c45]";
    if (typeof value === "string") colorClass = "text-[#1b5e3a]";
    else if (typeof value === "number") colorClass = "text-[#855300]";
    else if (typeof value === "boolean") colorClass = "text-[#590907]";

    return (
      <div className="leading-[20px] font-mono text-[13px] break-all max-w-full" style={{ paddingLeft: depth * 16 }}>
        {name && (
          <>
            <span className="text-[#590907] shrink-0">"{name}"</span>
            <span className="text-[#76786d]">: </span>
          </>
        )}
        <span className={`${colorClass} break-all`}>{JSON.stringify(value)}</span>
      </div>
    );
  }

  const entries = Object.entries(value as Record<string, unknown>);
  const isArray = Array.isArray(value);

  return (
    <div className="font-mono text-[13px] max-w-full">
      <button
        type="button"
        className="flex h-6 items-center text-left hover:opacity-80 transition cursor-pointer select-none max-w-full"
        style={{ paddingLeft: depth * 16 }}
        onClick={() => setOpen(!open)}
      >
        <ChevronRight
          className={`mr-1 size-3 text-[#76786d] shrink-0 transition-transform duration-150 ${
            open ? "rotate-90" : ""
          }`}
        />
        {name && (
          <>
            <span className="text-[#590907] shrink-0">"{name}"</span>
            <span className="text-[#76786d]">: </span>
          </>
        )}
        <span className="text-[#45483e] truncate">
          {isArray ? "[" : "{"}
          {!open && ` ${entries.length} items `}
          {!open && (isArray ? "]" : "}")}
        </span>
      </button>
      {open && (
        <div className="max-w-full">
          {entries.map(([key, child]) => (
            <Node key={key} name={key} value={child} depth={depth + 1} />
          ))}
          <div className="text-[#45483e] leading-[20px]" style={{ paddingLeft: depth * 16 }}>
            {isArray ? "]" : "}"}
          </div>
        </div>
      )}
    </div>
  );
}

export function JsonTree({ data }: { data: unknown }) {
  if (data === undefined) {
    return <div className="text-xs text-[#76786d] italic">No telemetry data</div>;
  }
  return (
    <div className="ui-json-tree overflow-x-auto overflow-y-auto font-mono text-[13px] text-[#1a1d15] p-2 break-all max-w-full">
      <Node value={data} />
    </div>
  );
}
