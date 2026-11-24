import { type FormEvent, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Check,
  ChevronLeft,
  ChevronRight,
  Clipboard,
  Copy,
  FileJson,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  Upload,
  Zap,
  X,
} from "lucide-react";
import {
  api,
  type UniversalLogEvent,
  type EventsResponse,
  type ApiKeyItem,
  type LogSourceItem,
  type StatsOverview,
  type FormatStatItem,
  type SandboxParseResponse,
} from "../lib/api";
import {
  Badge,
  Button,
  Card,
  Dialog,
  DialogButton,
  DialogField,
  DialogFooter,
  DialogWarning,
  Empty,
  Input,
  dialogInputClass,
} from "../components/ui";
import { JsonTree } from "../components/JsonTree";
import { Hero } from "../components/common/Hero";
import { PageBody } from "../components/common/PageBody";
import { SectionTitle } from "../components/common/SectionTitle";
import { CloudflareBarDropChart } from "../components/dashboard/CloudflareBarDropChart";
import { formatDate, severityTone, queryString } from "../utils/formatters";

// ---------------------------------------------------------------------------
// 1. Dashboard Page
// ---------------------------------------------------------------------------

export function DashboardPage() {
  const [range, setRange] = useState<"24h" | "7d" | "30d">("24h");
  const [loadingStats, setLoadingStats] = useState(true);
  const [overview, setOverview] = useState<StatsOverview>({
    total_events: 0,
    events_today: 0,
    avg_latency_ms: 0,
    active_sources_count: 0,
    threat_count: 0,
    rule_percentage: 0,
    template_percentage: 0,
    llm_percentage: 0,
  });

  const [timeline, setTimeline] = useState<{ time: string; count: number }[]>([]);
  const [formats, setFormats] = useState<FormatStatItem[]>([]);
  const [severity, setSeverity] = useState<{ level: string; count: number }[]>([]);
  const [threats, setThreats] = useState<{
    recent_iocs: { type: string; value: string; seen_at: string }[];
    top_techniques: { technique: string; count: number }[];
  }>({ recent_iocs: [], top_techniques: [] });

  const loadStats = () => {
    setLoadingStats(true);
    Promise.allSettled([
      api<StatsOverview>("/api/v1/stats").then((data) => setOverview(data)),
      api<{ formats: FormatStatItem[] }>("/api/v1/stats/formats").then((res) => setFormats(res.formats || [])),
      api<{ severity: { level: string; count: number }[] }>("/api/v1/stats/severity").then((res) => setSeverity(res.severity || [])),
      api<{
        recent_iocs: { type: string; value: string; seen_at: string }[];
        top_techniques: { technique: string; count: number }[];
      }>("/api/v1/stats/threats").then((res) => setThreats(res || { recent_iocs: [], top_techniques: [] })),
    ]).finally(() => setLoadingStats(false));
  };

  useEffect(() => {
    loadStats();
  }, []);

  // Fetch timeline whenever time range selection changes
  useEffect(() => {
    api<{ data: { time: string; count: number }[] }>(`/api/v1/stats/timeline?period=${range}`)
      .then((res) => setTimeline(res.data || []))
      .catch(() => setTimeline([]));
  }, [range]);

  const metrics = [
    ["Total Ingested Events", loadingStats ? "—" : (overview.total_events ?? 0), "All time"],
    ["Events (Last 24h)", loadingStats ? "—" : (overview.events_today ?? 0), "Active stream"],
    ["Active Collectors", loadingStats ? "—" : (overview.active_sources_count ?? 0), "Connected sources"],
    ["Avg Parse Latency", loadingStats ? "—" : `${(overview.avg_latency_ms ?? 0).toFixed(1)} ms`, "Per event"],
    ["Threat IOCs Tagged", loadingStats ? "—" : (overview.threat_count ?? 0), "MITRE ATT&CK"],
    ["Fast-Path Tier 1", loadingStats ? "—" : `${(overview.rule_percentage ?? 0).toFixed(1)}%`, "Rule / Regex"],
  ];

  const formatRows = formats;

  const defaultSeverities = [
    { level: "CRITICAL", count: 0 },
    { level: "ERROR", count: 0 },
    { level: "WARNING", count: 0 },
    { level: "INFORMATIONAL", count: 0 },
  ];
  const severityRows = severity.length ? severity : defaultSeverities;

  const cascadeTiers = [
    { tier: "1", label: "Rule / Regex Fast-Path", percentage: overview.rule_percentage ?? 0 },
    { tier: "2", label: "Drain3 Tree Templates", percentage: overview.template_percentage ?? 0 },
    { tier: "3", label: "NVIDIA NIM AI Inference", percentage: overview.llm_percentage ?? 0 },
  ];

  return (
    <>
      <Hero
        route="/dashboard"
        title="Dashboard"
        description="Live telemetry throughput, format distribution, and threat classification."
        status={
          <span className="inline-flex items-center gap-1.5 rounded-full bg-[#d8efe0] border border-[#1b5e3a]/20 px-3 py-1 font-mono text-xs text-[#0b331e]">
            <span className="size-2 rounded-full bg-[#1b5e3a] animate-pulse" />
            Pipeline Healthy
          </span>
        }
        actions={
          <>
            <Button variant="secondary" onClick={() => loadStats()}>
              <RefreshCw className="size-4" />
              Refresh
            </Button>
            <Link to="/sandbox">
              <Button>Open Sandbox</Button>
            </Link>
          </>
        }
      />
      <PageBody>
        {/* Metric Cards Grid */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {metrics.map(([label, value, note]) => (
            <Card key={label as string} className="flex h-[92px] items-center justify-between p-5">
              <div>
                <p className="font-ui-medium text-xs text-[#45483e]">{label}</p>
                <p
                  className={`font-heading-semibold mt-1 text-[26px] leading-[30px] ${
                    label === "Threat IOCs Tagged" ? "text-[#93000a]" : "text-[#1a1d15]"
                  }`}
                >
                  {typeof value === "number" ? value.toLocaleString() : value}
                </p>
              </div>
              <span className="font-mono-medium rounded-full border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 text-xs text-[#45483e]">
                {note}
              </span>
            </Card>
          ))}
        </div>

        {/* Ingestion Timeline Chart */}
        <Card className="p-6">
          <SectionTitle
            title={`Ingestion Timeline (${range === "24h" ? "24 Hours" : range === "7d" ? "7 Days" : "30 Days"})`}
            description="Events processed per bucket across all active collectors and API keys."
            side={
              <div className="inline-flex items-center rounded-lg border border-[#c6c8bb] bg-[#efe6da] p-0.5 text-xs font-mono">
                {(["24h", "7d", "30d"] as const).map((r) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setRange(r)}
                    className={`rounded px-3 py-1 font-semibold transition cursor-pointer ${
                      range === r
                        ? "bg-white text-[#590907] shadow-xs"
                        : "text-[#45483e] hover:text-[#1a1d15]"
                    }`}
                  >
                    {r}
                  </button>
                ))}
              </div>
            }
          />
          <div className="mt-5">
            <CloudflareBarDropChart data={timeline} period={range} />
          </div>
          <div className="font-mono-medium mt-2 flex justify-between text-[11px] text-[#76786d]">
            {range === "24h" ? (
              <>
                <span>24h ago</span>
                <span>18h ago</span>
                <span>12h ago</span>
                <span>6h ago</span>
                <span>Current (Live)</span>
              </>
            ) : range === "7d" ? (
              <>
                <span>7 days ago</span>
                <span>5 days ago</span>
                <span>3 days ago</span>
                <span>Yesterday</span>
                <span>Current (Live)</span>
              </>
            ) : (
              <>
                <span>30 days ago</span>
                <span>20 days ago</span>
                <span>10 days ago</span>
                <span>5 days ago</span>
                <span>Current (Live)</span>
              </>
            )}
          </div>
        </Card>

        {/* Format & Severity Distributions */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Format Distribution */}
          <Card className="p-6">
            <SectionTitle
              title="Format Distribution"
              side={
                <span className="font-mono-medium text-xs text-[#45483e]">
                  {formatRows.length} standards active
                </span>
              }
            />
            {formatRows.length ? (
              <div className="mt-4 space-y-3.5">
                {formatRows.map((item, index) => (
                  <div key={item.format}>
                    <div className="font-mono-medium mb-1 flex justify-between text-xs">
                      <span className="text-[#1a1d15] font-semibold">{item.format}</span>
                      <span className="text-[#45483e]">
                        {item.count.toLocaleString()} ({item.percentage}%)
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-[#f6efe5] overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${
                          index === 0
                            ? "bg-[#590907]"
                            : index === 1
                            ? "bg-[#812720]"
                            : index === 2
                            ? "bg-[#45483e]"
                            : "bg-[#76786d]"
                        }`}
                        style={{ width: `${item.percentage}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-4 flex flex-col items-center justify-center rounded-lg border border-dashed border-[#c6c8bb] bg-[#faf6f0] p-8 text-center">
                <p className="font-ui-medium text-sm text-[#1a1d15]">No Telemetry Formats Recorded</p>
                <p className="font-ui text-xs text-[#76786d] mt-1">
                  Active format distributions will appear as events stream into LogMorph.
                </p>
              </div>
            )}
          </Card>

          {/* Severity Breakdown */}
          <Card className="p-6">
            <SectionTitle
              title="Severity Breakdown"
              side={
                <span className="font-mono-medium text-xs text-[#45483e]">
                  RFC 5424 Classification
                </span>
              }
            />
            <div className="mt-3 space-y-1">
              {severityRows.map((item) => (
                <div
                  key={item.level}
                  className="flex items-center justify-between border-b border-[#c6c8bb]/60 py-2.5 last:border-0"
                >
                  <Badge tone={severityTone(item.level)}>{item.level}</Badge>
                  <span className="font-mono-medium text-xs text-[#1a1d15] font-semibold">
                    {item.count.toLocaleString()} events
                  </span>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* 3-Tier Parsing Cascade & Threat IOCs */}
        <div className="grid gap-6 xl:grid-cols-[5fr_7fr]">
          <Card className="p-6">
            <SectionTitle
              title="3-Tier Parsing Cascade"
              side={<span className="font-mono-medium text-xs text-[#590907] font-semibold">Sub-ms Path</span>}
            />
            <div className="mt-5 flex h-3.5 overflow-hidden rounded-full bg-[#f6efe5] border border-[#c6c8bb]/40">
              {cascadeTiers.map((item, index) => (
                <div
                  key={item.tier}
                  className={
                    index === 0
                      ? "bg-[#1b5e3a]"
                      : index === 1
                      ? "bg-[#5a3800]"
                      : "bg-[#590907]"
                  }
                  style={{ width: `${item.percentage}%` }}
                />
              ))}
            </div>
            <div className="mt-5 space-y-1">
              {cascadeTiers.map((item, index) => (
                <div
                  key={item.tier}
                  className="flex justify-between border-b border-[#c6c8bb]/60 py-2.5 text-sm last:border-0"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`size-2 rounded-full ${
                        index === 0
                          ? "bg-[#1b5e3a]"
                          : index === 1
                          ? "bg-[#5a3800]"
                          : "bg-[#590907]"
                      }`}
                    />
                    <span className="font-ui-medium text-[#1a1d15]">
                      Tier {item.tier} · {item.label}
                    </span>
                  </div>
                  <span className="font-mono-medium text-xs text-[#45483e]">
                    {Number(item.percentage || 0).toFixed(1)}%
                  </span>
                </div>
              ))}
            </div>
          </Card>

          <Card className="p-6">
            <SectionTitle
              title="Top MITRE ATT&CK Detections"
              side={
                <Badge tone={threats.recent_iocs.length > 0 ? "red" : "neutral"}>
                  {threats.recent_iocs.length} Threat Techniques
                </Badge>
              }
            />
            {threats.top_techniques.length ? (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#c6c8bb]">
                      <th className="py-2.5 font-medium text-[#45483e]">Technique</th>
                      <th className="py-2.5 font-medium text-[#45483e] text-right">Detections</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.top_techniques.map((item) => (
                      <tr key={item.technique} className="border-b border-[#c6c8bb]/60 last:border-0">
                        <td className="py-2.5 font-mono text-[#590907] font-semibold">
                          {item.technique}
                        </td>
                        <td className="py-2.5 font-mono text-right text-[#1a1d15]">
                          {item.count}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="mt-4 flex flex-col items-center justify-center rounded-lg border border-dashed border-[#c6c8bb] bg-[#faf6f0] p-8 text-center">
                <p className="font-ui-medium text-sm text-[#1a1d15]">No Threat IOCs Detected</p>
                <p className="font-ui text-xs text-[#76786d] mt-1">
                  Adversary techniques and IOC detections will appear dynamically as suspicious events are processed.
                </p>
              </div>
            )}
          </Card>
        </div>
      </PageBody>
    </>
  );
}

// ---------------------------------------------------------------------------
// 2. Log Explorer Page
// ---------------------------------------------------------------------------

function EventTable({ events }: { events: UniversalLogEvent[] }) {
  const navigate = useNavigate();

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[1050px] text-left text-xs">
        <thead className="bg-[#f6efe5] border-b border-[#c6c8bb]">
          <tr>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Timestamp</th>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Severity</th>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Format</th>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Source Host/IP</th>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Action</th>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Parsed By</th>
            <th className="px-4 py-3 font-semibold text-[#1a1d15]">Raw Log Line</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#c6c8bb]/60">
          {events.map((event) => (
            <tr
              key={event.event_id}
              onClick={() => navigate(`/logs/${event.event_id}`)}
              className="cursor-pointer hover:bg-[#faf6f0] transition-colors"
            >
              <td className="whitespace-nowrap px-4 py-3 font-mono text-[#45483e]">
                {formatDate(event.timestamp)}
              </td>
              <td className="px-4 py-3">
                <Badge tone={severityTone(event.severity)}>{event.severity}</Badge>
              </td>
              <td className="px-4 py-3">
                <span className="rounded-full bg-[#e8d2b5] px-2 py-0.5 font-mono text-[11px] font-semibold text-[#590907]">
                  {event.detected_format}
                </span>
              </td>
              <td className="px-4 py-3 font-mono text-xs text-[#1a1d15]">
                {event.source?.hostname || event.source?.ip || "—"}
              </td>
              <td className="px-4 py-3 font-mono text-[#590907] font-semibold">
                {event.action || "—"}
              </td>
              <td className="px-4 py-3">
                <Badge tone={event.parsed_by === "RULE" ? "green" : event.parsed_by === "TEMPLATE" ? "sage" : "violet"}>
                  {event.parsed_by || "RULE"}
                </Badge>
              </td>
              <td className="max-w-[320px] truncate px-4 py-3 font-mono text-[#76786d]">
                {event.raw_log}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function LogsPage() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") || "");
  const [events, setEvents] = useState<UniversalLogEvent[]>([]);
  const [pagination, setPagination] = useState({ page: 1, total: 0, total_pages: 1, limit: 25 });
  const [loading, setLoading] = useState(true);
  const [sourcesList, setSourcesList] = useState<string[]>([]);

  const severity = params.get("severity") || "";
  const format = params.get("format") || "";
  const source = params.get("source") || "";
  const page = Number(params.get("page") || 1);
  const q = params.get("q") || "";

  // Load registered sources dynamically from backend API
  useEffect(() => {
    api<{ sources: LogSourceItem[] }>("/api/v1/sources")
      .then((res) => {
        if (res.sources?.length) {
          const names = Array.from(
            new Set(res.sources.map((s) => s.name).filter(Boolean))
          );
          if (names.length) setSourcesList(names);
        }
      })
      .catch(() => {});
  }, []);

  // Sync internal search input with URL params if changed externally
  useEffect(() => {
    setSearch(params.get("q") || "");
  }, [params]);

  // Debounced auto-sync from input text to URL query
  useEffect(() => {
    const timer = setTimeout(() => {
      const currentParam = params.get("q") || "";
      const trimmed = search.trim();
      if (trimmed !== currentParam) {
        const next = new URLSearchParams(params);
        if (trimmed) next.set("q", trimmed);
        else next.delete("q");
        next.delete("page");
        setParams(next, { replace: true });
      }
    }, 350);

    return () => clearTimeout(timer);
  }, [search]);

  // Fetch telemetry events when query params change
  useEffect(() => {
    let active = true;
    setLoading(true);

    api<EventsResponse>(
      `/api/v1/events?${queryString({
        page,
        limit: 25,
        search: q || undefined,
        severity: severity && severity !== "ALL" ? severity : undefined,
        format: format && format !== "ALL" ? format : undefined,
        source: source || undefined,
      })}`
    )
      .then((res) => {
        if (!active) return;
        setEvents(res.events || []);
        setPagination(
          res.pagination || { page: 1, total: res.events?.length || 0, total_pages: 1, limit: 25 }
        );
      })
      .catch(() => {
        if (!active) return;
        setEvents([]);
        setPagination({ page: 1, total: 0, total_pages: 1, limit: 25 });
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [q, severity, format, source, page]);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    value ? next.set(key, value) : next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next);
  };

  const handleApply = () => {
    const next = new URLSearchParams(params);
    if (search.trim()) next.set("q", search.trim());
    else next.delete("q");
    next.delete("page");
    setParams(next);
  };

  const handleClearSearch = () => {
    setSearch("");
    const next = new URLSearchParams(params);
    next.delete("q");
    next.delete("page");
    setParams(next);
  };

  const handleClearAll = () => {
    setSearch("");
    setParams(new URLSearchParams());
  };

  return (
    <>
      <Hero
        route="/logs"
        title="Log Explorer"
        description="Search, filter, and inspect normalized UniversalLogEvent records across all active sources."
        status={
          <span className="rounded-full border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 text-xs font-mono text-[#45483e]">
            ● {pagination.total.toLocaleString()} indexed records
          </span>
        }
        actions={
          <>
            <Button
              variant="secondary"
              onClick={() => setParams(new URLSearchParams(params))}
            >
              <RefreshCw className="size-4" />
              Refresh
            </Button>
            <Link to="/sandbox">
              <Button variant="secondary">Open Sandbox</Button>
            </Link>
          </>
        }
      />
      <PageBody>
        {/* Filter Controls Bar */}
        <Card className="grid gap-3 p-4 lg:grid-cols-[1fr_150px_140px_170px_auto] lg:items-end">
          <label className="block">
            <span className="font-ui-medium text-xs text-[#45483e]">Search Telemetry</span>
            <div className="relative mt-1">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[#76786d]" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleApply();
                  }
                }}
                placeholder="Search by IP, hostname, action, message…"
                className="h-[38px] w-full rounded-lg border border-[#c6c8bb] bg-[#f6efe5] pl-9 pr-9 text-sm outline-none focus:border-[#590907] focus:bg-white transition"
              />
              {search && (
                <button
                  type="button"
                  onClick={handleClearSearch}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#76786d] hover:text-[#1a1d15] cursor-pointer"
                >
                  <X className="size-4" />
                </button>
              )}
            </div>
          </label>

          {[
            [
              "Severity",
              "severity",
              severity,
              ["", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"],
            ],
            [
              "Format",
              "format",
              format,
              ["", "SYSLOG", "JSON", "CEF", "LEEF", "CLF", "UNSTRUCTURED"],
            ],
            ["Source Node", "source", source, ["", ...sourcesList]],
          ].map(([label, key, val, options]) => (
            <label key={key as string}>
              <span className="font-ui-medium text-xs text-[#45483e]">{label as string}</span>
              <select
                value={val as string}
                onChange={(e) => setFilter(key as string, e.target.value)}
                className="mt-1 h-[38px] w-full rounded-lg border border-[#c6c8bb] bg-[#f6efe5] px-3 text-sm outline-none focus:border-[#590907] cursor-pointer"
              >
                <option value="">All {String(label).toLowerCase()}s</option>
                {(options as string[]).filter(Boolean).map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </select>
            </label>
          ))}

          <Button onClick={handleApply}>Apply Filters</Button>
        </Card>

        {/* Events Table Container */}
        <Card className="overflow-hidden">
          {loading ? (
            <div className="grid h-72 place-items-center">
              <RefreshCw className="size-6 animate-spin text-[#590907]" />
            </div>
          ) : events.length ? (
            <EventTable events={events} />
          ) : (
            <Empty
              text="No log events match your current filter criteria."
              action={
                <Button variant="secondary" onClick={handleClearAll}>
                  Clear All Filters
                </Button>
              }
            />
          )}

          {/* Pagination Footer */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#c6c8bb] bg-[#f6efe5] px-5 py-3 text-sm text-[#45483e]">
            <span>
              Showing {events.length ? (page - 1) * pagination.limit + 1 : 0}–
              {Math.min(page * pagination.limit, pagination.total)} of{" "}
              {pagination.total.toLocaleString()} events
            </span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setFilter("page", String(page - 1))}
                className="rounded-lg border border-[#c6c8bb] bg-white p-2 hover:bg-[#faf6f0] disabled:opacity-40 cursor-pointer"
              >
                <ChevronLeft className="size-4" />
              </button>
              <span className="grid size-9 place-items-center rounded-lg bg-[#590907] text-xs font-semibold text-white">
                {page}
              </span>
              <button
                type="button"
                disabled={page >= pagination.total_pages}
                onClick={() => setFilter("page", String(page + 1))}
                className="rounded-lg border border-[#c6c8bb] bg-white p-2 hover:bg-[#faf6f0] disabled:opacity-40 cursor-pointer"
              >
                <ChevronRight className="size-4" />
              </button>
            </div>
          </div>
        </Card>
      </PageBody>
    </>
  );
}

// ---------------------------------------------------------------------------
// 3. Event Detail Page
// ---------------------------------------------------------------------------

export function EventDetailPage() {
  const { eventId } = useParams();
  const navigate = useNavigate();
  const [event, setEvent] = useState<UniversalLogEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!eventId) return;
    setLoading(true);
    setError(null);
    api<UniversalLogEvent>(`/api/v1/events/${eventId}`)
      .then((res) => setEvent(res))
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Event not found");
        setEvent(null);
      })
      .finally(() => setLoading(false));
  }, [eventId]);

  if (loading) {
    return (
      <div className="grid h-screen place-items-center">
        <RefreshCw className="size-6 animate-spin text-[#590907]" />
      </div>
    );
  }

  if (error || !event) {
    return (
      <div className="mx-auto max-w-xl px-4 py-20 text-center">
        <div className="rounded-2xl border border-[#c6c8bb] bg-white p-8 shadow-sm">
          <div className="mx-auto mb-4 grid size-12 place-items-center rounded-full bg-[#ffdad5] text-[#93000a]">
            <AlertCircle className="size-6" />
          </div>
          <h2 className="font-heading-semibold text-lg text-[#1a1d15]">Event Not Found</h2>
          <p className="mt-2 text-sm text-[#45483e]">
            {error || `No telemetry record exists with ID "${eventId}".`}
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <Link to="/logs">
              <Button>Back to Log Explorer</Button>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const copy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const remove = async () => {
    if (!confirm("Delete this telemetry event? This cannot be undone.")) return;
    try {
      await api(`/api/v1/events/${event.event_id}`, { method: "DELETE" });
    } catch {
      // Ignored
    }
    navigate("/logs");
  };

  return (
    <>
      <header className="border-b border-[#c6c8bb] bg-white px-5 pb-6 pt-6 sm:px-8 shadow-xs">
        <div className="mx-auto max-w-[1280px]">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <Link
              to="/logs"
              className="font-ui-medium flex items-center gap-2 text-sm text-[#45483e] hover:text-[#590907] transition"
            >
              <ArrowLeft className="size-4" />
              <span>Back to Log Explorer</span>
              <span className="font-mono text-xs text-[#590907]">/logs/{event.event_id}</span>
            </Link>
            <span className="font-mono-medium text-xs text-[#76786d]">
              {formatDate(event.timestamp)}
            </span>
          </div>
          <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="font-heading-semibold text-[26px] leading-[32px] text-[#1a1d15]">
                Event{" "}
                <span className="rounded-lg border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 font-mono text-sm font-normal text-[#1a1d15]">
                  {event.event_id}
                </span>
              </h1>
              <Badge tone={severityTone(event.severity)}>{event.severity}</Badge>
              <Badge tone="violet">Cascade Tier · {event.parsed_by || "RULE"}</Badge>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="secondary" onClick={remove} className="text-[#93000a]">
                <Trash2 className="size-4 mr-1" />
                Delete
              </Button>
              <Button
                variant="secondary"
                onClick={() => copy(JSON.stringify(event, null, 2))}
              >
                <Copy className="size-4 mr-1" />
                Copy ULS JSON
              </Button>
              <Link to="/sandbox">
                <Button>Open in Sandbox</Button>
              </Link>
            </div>
          </div>
        </div>
      </header>

      <PageBody>
        {/* Raw Log line vs. Parsed ULS JSON */}
        <div className="grid gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <Card className="p-6 min-w-0 overflow-hidden">
            <SectionTitle
              title="Raw Log Line"
              side={
                <button
                  type="button"
                  onClick={() => copy(event.raw_log)}
                  className="grid size-8 place-items-center rounded-lg border border-[#c6c8bb] bg-[#f6efe5] hover:bg-[#efe6da] transition cursor-pointer"
                >
                  {copied ? <Check className="size-4 text-[#1b5e3a]" /> : <Copy className="size-4 text-[#45483e]" />}
                </button>
              }
            />
            <div className="mt-3">
              <Badge tone="violet">{event.detected_format}</Badge>
            </div>
            <pre className="mt-3 whitespace-pre-wrap break-all overflow-x-auto rounded-lg border border-[#c6c8bb] bg-[#f6efe5] p-4 font-mono text-[13px] leading-[21px] text-[#1a1d15]">
              {event.raw_log}
            </pre>
            {event.attributes && (
              <div className="mt-5 space-y-1 overflow-hidden">
                <p className="font-ui-medium text-xs text-[#76786d] uppercase tracking-wider mb-2">
                  Extracted Attributes
                </p>
                {Object.entries(event.attributes).map(([key, value]) => (
                  <div
                    key={key}
                    className="flex justify-between gap-4 border-t border-[#c6c8bb]/60 py-2 font-mono text-xs min-w-0"
                  >
                    <span className="shrink-0 text-[#45483e]">attributes.{key}</span>
                    <span className="max-w-[60%] truncate text-right text-[#1a1d15]" title={String(value)}>
                      {String(value)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card className="p-6 min-w-0 overflow-hidden">
            <SectionTitle
              title="Normalized UniversalLogEvent (ULS)"
              side={
                <span className="rounded-lg border border-[#c6c8bb] bg-[#efe6da] px-2.5 py-1 text-xs font-mono font-medium text-[#590907]">
                  Standardized JSON
                </span>
              }
            />
            <div className="mt-4 max-h-[560px] overflow-auto rounded-lg border border-[#c6c8bb] bg-[#f6efe5] p-4 min-w-0">
              <JsonTree data={event} />
            </div>
          </Card>
        </div>

        {/* Enrichment Cards: GeoIP, Threat Intel, MITRE ATT&CK */}
        <div className="grid gap-6 md:grid-cols-3">
          <Card className="p-6">
            <SectionTitle
              title="GeoIP Enrichment"
              side={
                <span className="font-mono-medium text-xs text-[#590907]">
                  {event.enrichment?.geoip?.country || "Enriched"}
                </span>
              }
            />
            <p className="mt-3 text-sm text-[#45483e]">
              {event.enrichment?.geoip
                ? `${event.enrichment.geoip.city || "City"}, ${event.enrichment.geoip.country || "Country"}`
                : "IP source within private internal CIDR block."}
            </p>
          </Card>

          <Card className="p-6">
            <SectionTitle
              title="Threat Intelligence"
              side={
                <Badge tone={event.enrichment?.threat_match ? "red" : "green"}>
                  {event.enrichment?.threat_match ? "Active Threat Match" : "Clear · No Known IOC"}
                </Badge>
              }
            />
            <p className="mt-3 text-sm text-[#45483e]">
              {event.enrichment?.threat_match
                ? "This source IP matched known malicious adversary infrastructure."
                : "Source clean against active threat intelligence feeds."}
            </p>
          </Card>

          <Card className="p-6">
            <SectionTitle
              title="MITRE ATT&CK Mapping"
              side={
                event.enrichment?.mitre_technique ? (
                  <Badge tone="violet">
                    {event.enrichment.mitre_technique.split(" ")[0]}
                  </Badge>
                ) : undefined
              }
            />
            <p className="mt-3 text-sm text-[#45483e]">
              {event.enrichment?.mitre_technique || "No adversarial technique mapped to event."}
            </p>
          </Card>
        </div>
      </PageBody>
    </>
  );
}

// ---------------------------------------------------------------------------
// 4. Sandbox Page
// ---------------------------------------------------------------------------

const sandboxSamples = {
  Syslog: `<34>Oct 11 22:14:15 edge-fw-01 sshd[1842]: Failed password for root from 185.220.101.4 port 51822 ssh2`,
  JSON: `{"timestamp":"2026-03-08T14:22:31Z","level":"error","service":"payments-api","message":"upstream database query timed out after 5000ms","duration_ms":5002}`,
  CEF: `CEF:0|Security|Firewall|2.1|100|Blocked connection|7|src=10.0.0.4 dst=185.220.101.4 spt=51234 dpt=443 act=blocked`,
  Apache: `192.168.1.17 - - [08/Mar/2026:14:22:31 +0000] "GET /admin HTTP/1.1" 403 278 "-" "Mozilla/5.0"`,
};

export function SandboxPage() {
  const [sample, setSample] = useState<keyof typeof sandboxSamples>("Syslog");
  const [raw, setRaw] = useState(sandboxSamples.Syslog);
  const [result, setResult] = useState<SandboxParseResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [latency, setLatency] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [copiedUls, setCopiedUls] = useState(false);

  // Client-side JSON syntax check if payload looks like JSON
  const isJsonCandidate = raw.trim().startsWith("{") || raw.trim().startsWith("[");
  let jsonSyntaxError: string | null = null;
  if (isJsonCandidate) {
    try {
      JSON.parse(raw.trim());
    } catch (e) {
      jsonSyntaxError = e instanceof Error ? e.message : "Invalid JSON syntax";
    }
  }

  const parse = async () => {
    const trimmed = raw.trim();
    if (!trimmed) {
      setError("Please enter or paste a log line, or select a sample above.");
      return;
    }
    if (trimmed.length > 8192) {
      setError(
        `Log payload exceeds 8,192 character maximum (${trimmed.length.toLocaleString()} characters). Please shorten the payload.`
      );
      return;
    }

    setLoading(true);
    setError(null);
    const start = performance.now();
    try {
      const res = await api<SandboxParseResponse>("/api/v1/sandbox/parse", {
        method: "POST",
        body: JSON.stringify({ raw_log: trimmed }),
      });
      setResult(res);
      setLatency(res.processing_ms || Math.max(1, Math.round(performance.now() - start)));
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Parsing service temporarily unavailable");
    } finally {
      setLoading(false);
    }
  };

  const copyUls = () => {
    if (!result?.event) return;
    try {
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(JSON.stringify(result.event, null, 2)).catch(() => {});
      }
    } catch {
      // Safe fallback
    }
    setCopiedUls(true);
    setTimeout(() => setCopiedUls(false), 2000);
  };

  return (
    <>
      <Hero
        route="/sandbox"
        title="Interactive Sandbox"
        description="Test format detection, Drain3 templates, and UniversalLogEvent normalization in real time."
        status={
          <span className="rounded-full bg-[#e8d2b5] px-3 py-1 text-xs font-mono font-medium text-[#590907]">
            Dry-Run Mode · Zero Persistence
          </span>
        }
        actions={
          <div className="font-mono-medium hidden items-center gap-1.5 text-xs xl:flex">
            <Badge tone="green">1. Rule/Regex</Badge>
            <span>→</span>
            <Badge tone="amber">2. Drain3</Badge>
            <span>→</span>
            <Badge tone="violet">3. NVIDIA NIM</Badge>
          </div>
        }
      />
      <PageBody className="xl:grid xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Card className="flex min-h-[620px] flex-col p-6 min-w-0 overflow-hidden">
          <SectionTitle
            title="Raw Log Input"
            side={<span className="font-ui-medium text-xs text-[#76786d]">Immediate Dry-Run</span>}
          />
          <label className="mt-4">
            <span className="font-ui-medium text-xs text-[#45483e]">Load Pre-configured Sample</span>
            <select
              value={sample}
              onChange={(e) => {
                const next = e.target.value as keyof typeof sandboxSamples;
                setSample(next);
                setRaw(sandboxSamples[next]);
                setError(null);
                setResult(null);
              }}
              className="mt-1 h-10 w-full rounded-lg border border-[#c6c8bb] bg-[#f6efe5] px-3 text-sm outline-none focus:border-[#590907] cursor-pointer"
            >
              {Object.keys(sandboxSamples).map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
            <span className="font-ui-medium text-xs text-[#1a1d15]">Paste or type raw telemetry</span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={async () => {
                  try {
                    const text = await navigator.clipboard.readText();
                    if (text) {
                      setRaw(text);
                      setError(null);
                    }
                  } catch {
                    // Clipboard permissions
                  }
                }}
                className="flex items-center gap-1.5 rounded border border-[#c6c8bb] bg-[#f6efe5] px-3 py-1 text-xs text-[#1a1d15] hover:bg-[#efe6da] transition cursor-pointer"
              >
                <Clipboard className="size-3" />
                <span>Paste</span>
              </button>
              <label className="flex cursor-pointer items-center gap-1.5 rounded border border-[#c6c8bb] bg-[#f6efe5] px-3 py-1 text-xs text-[#1a1d15] hover:bg-[#efe6da] transition">
                <Upload className="size-3" />
                <span>Upload</span>
                <input
                  type="file"
                  accept=".log,.txt,.json"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      file.text().then((text) => {
                        setRaw(text);
                        setError(null);
                      });
                    }
                  }}
                />
              </label>
            </div>
          </div>

          <textarea
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              if (error) setError(null);
            }}
            placeholder="Paste raw log lines or JSON documents here..."
            className="mt-2 min-h-60 flex-1 resize-none rounded-lg border-2 border-dashed border-[#c6c8bb] bg-[#f6efe5] p-4 font-mono text-[13px] leading-[21px] text-[#1a1d15] outline-none focus:border-[#590907] focus:bg-white transition"
          />

          {/* Character Counter & Syntax Helpers */}
          <div className="mt-2 flex items-center justify-between text-xs font-mono text-[#76786d]">
            <span>{raw.length.toLocaleString()} / 8,192 characters</span>
            {raw.length > 8192 ? (
              <span className="font-semibold text-[#93000a]">Payload exceeds 8,192 limit</span>
            ) : isJsonCandidate && !jsonSyntaxError ? (
              <span className="text-[#1b5e3a] font-semibold">Valid JSON Syntax</span>
            ) : null}
          </div>

          {/* JSON Syntax Alert */}
          {jsonSyntaxError && (
            <div className="mt-2 flex items-start gap-2 rounded-lg border border-[#855300]/30 bg-[#f6dfc2] p-2.5 text-xs text-[#5a3800]">
              <AlertTriangle className="size-4 shrink-0 text-[#855300] mt-0.5" />
              <div>
                <strong className="font-semibold">JSON Syntax Warning:</strong> {jsonSyntaxError}. Check quotes or trailing commas for Tier 1 JSON normalization.
              </div>
            </div>
          )}

          <div className="mt-4 flex gap-2 border-t border-[#c6c8bb] pt-4">
            <Button
              className="flex-1"
              onClick={parse}
              loading={loading}
              disabled={raw.length > 8192}
            >
              <Zap className="size-4" />
              Parse Telemetry
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setRaw("");
                setResult(null);
                setError(null);
                setLatency(null);
              }}
            >
              Clear
            </Button>
          </div>
        </Card>

        <Card className="flex min-h-[620px] flex-col p-6 min-w-0 overflow-hidden">
          <SectionTitle
            title="Parsed Output (ULS)"
            side={
              latency !== null && !error ? (
                <span className="font-mono-medium text-xs text-[#1b5e3a] font-semibold">
                  Parsed in {latency} ms
                </span>
              ) : undefined
            }
          />

          {error ? (
            <div className="mt-4 rounded-lg border border-[#93000a]/30 bg-[#ffdad6] p-4 text-[#93000a]">
              <div className="flex items-center gap-2 font-heading-semibold text-sm">
                <AlertCircle className="size-4.5 text-[#93000a]" />
                <span>Submission / Parsing Error</span>
              </div>
              <p className="mt-1 text-xs leading-5 text-[#410002]">{error}</p>
              <div className="mt-3 rounded border border-[#93000a]/20 bg-white/70 p-2.5 text-[11px] text-[#410002]">
                <strong>Debugging Tips:</strong>
                <ul className="mt-1 list-disc pl-4 space-y-0.5 font-mono">
                  <li>Input must contain between 1 and 8,192 characters.</li>
                  <li>Ensure JSON keys and strings use valid double quotes.</li>
                  <li>Security attack payloads may be blocked by edge WAF filters.</li>
                </ul>
              </div>
            </div>
          ) : result && result.event ? (
            <>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-b border-[#c6c8bb]/60 pb-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="cyan">{result.detected_format} FORMAT</Badge>
                  <Badge
                    tone={
                      result.parsed_by === "RULE"
                        ? "green"
                        : result.parsed_by === "TEMPLATE"
                        ? "sage"
                        : "violet"
                    }
                  >
                    TIER {result.parsed_by}
                  </Badge>
                  <Badge tone="green">Normalization Verified</Badge>
                </div>
                <button
                  type="button"
                  onClick={copyUls}
                  className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs font-medium transition cursor-pointer ${
                    copiedUls
                      ? "border-[#1b5e3a] bg-[#d8efe0] text-[#0b331e]"
                      : "border-[#c6c8bb] bg-[#f6efe5] text-[#1a1d15] hover:bg-[#efe6da]"
                  }`}
                >
                  {copiedUls ? <Check className="size-3.5 text-[#1b5e3a]" /> : <Copy className="size-3.5" />}
                  <span>{copiedUls ? "Copied ULS" : "Copy ULS JSON"}</span>
                </button>
              </div>
              <div className="mt-3 min-h-0 flex-1 overflow-auto rounded-lg border border-[#c6c8bb] bg-[#f6efe5] p-4">
                <JsonTree data={result.event} />
              </div>
            </>
          ) : (
            <div className="grid flex-1 place-items-center text-center">
              <div>
                <FileJson className="mx-auto size-10 text-[#590907]" />
                <p className="mt-3 text-sm text-[#45483e]">
                  Click "Parse Telemetry" to inspect the normalized output.
                </p>
              </div>
            </div>
          )}
        </Card>
      </PageBody>
    </>
  );
}

// ---------------------------------------------------------------------------
// 5. API Keys Page
// ---------------------------------------------------------------------------

const codeSnippets: Record<string, string> = {
  cURL: `curl -X POST https://logmorph.onrender.com/api/v1/ingest \\
  -H "Authorization: Bearer lm_live_YOUR_KEY_HERE" \\
  -H "Content-Type: application/json" \\
  -d '{"raw_log":"<34>Oct 11 22:14:15 host sshd: login failed"}'`,
  Python: `import requests

requests.post(
  "https://logmorph.onrender.com/api/v1/ingest",
  headers={"Authorization": "Bearer lm_live_YOUR_KEY_HERE"},
  json={"raw_log": raw_log, "source": "production-firewall"}
)`,
};

export function KeysPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [createdSecret, setCreatedSecret] = useState("");
  const [createdKeyName, setCreatedKeyName] = useState("");
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<ApiKeyItem | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeSnippetTab, setActiveSnippetTab] = useState("cURL");

  const loadKeys = () =>
    api<{ keys: ApiKeyItem[] }>("/api/v1/keys")
      .then((res) => setKeys(res.keys || []))
      .catch(() => {});

  useEffect(() => {
    loadKeys();
  }, []);

  const createKey = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await api<{ key: string; name: string }>("/api/v1/keys", {
        method: "POST",
        body: JSON.stringify({ name: keyName }),
      });
      setCreatedKeyName(keyName);
      setCreatedSecret(res.key || "");
      loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate API key");
    } finally {
      setLoading(false);
    }
  };

  const revokeKey = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    try {
      await api(`/api/v1/keys/${revokeTarget.id}`, { method: "DELETE" });
      setRevokeTarget(null);
      loadKeys();
    } catch {
      // Ignored
    } finally {
      setRevoking(false);
    }
  };

  const closeCreationModal = () => {
    setModalOpen(false);
    setKeyName("");
    setCreatedSecret("");
    setCreatedKeyName("");
    setCopiedSecret(false);
    setError("");
  };

  return (
    <>
      <Hero
        route="/keys"
        title="API Keys"
        description="Generate and revoke ingestion keys for external collectors, log shippers, and firewalls."
        status={
          <span className="rounded-full border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 text-xs font-mono text-[#590907]">
            Bearer lm_live_*
          </span>
        }
        actions={
          <Button onClick={() => setModalOpen(true)}>
            <Plus className="size-4" />
            Generate New Key
          </Button>
        }
      />
      <PageBody>
        <Card className="overflow-hidden">
          {keys.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[800px] text-left text-sm">
                <thead className="bg-[#f6efe5] border-b border-[#c6c8bb]">
                  <tr>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Name</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Key Prefix</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Created</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Last Used</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Status</th>
                    <th className="px-5 py-3 text-right font-semibold text-[#1a1d15]">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#c6c8bb]/60">
                  {keys.map((k) => (
                    <tr key={k.id} className="hover:bg-[#faf6f0] transition-colors">
                      <td className="px-5 py-4 font-medium text-[#1a1d15]">{k.name}</td>
                      <td className="px-5 py-4 font-mono text-xs text-[#590907] font-semibold">
                        {k.key_prefix || "••••••••"}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-[#45483e]">
                        {formatDate(k.created_at)}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-[#45483e]">
                        {formatDate(k.last_used_at)}
                      </td>
                      <td className="px-5 py-4">
                        <Badge tone={k.is_active ? "green" : "neutral"}>
                          {k.is_active ? "Active" : "Revoked"}
                        </Badge>
                      </td>
                      <td className="px-5 py-4 text-right">
                        <Button
                          variant="secondary"
                          className="h-8 px-3 text-xs text-[#93000a] hover:bg-[#ffdad5]"
                          onClick={() => setRevokeTarget(k)}
                        >
                          Revoke
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              text="No ingestion keys generated yet. Create one to authenticate external collectors."
              action={
                <Button onClick={() => setModalOpen(true)}>
                  <Plus className="size-4" /> Generate Ingestion Key
                </Button>
              }
            />
          )}
        </Card>

        {/* Ingestion Quickstart Snippets */}
        <Card className="p-6">
          <SectionTitle
            title="Ingestion Quickstart"
            description="Send raw logs from your services using your Bearer API key."
            side={
              <div className="rounded-lg border border-[#c6c8bb] bg-[#efe6da] p-1 text-xs">
                {Object.keys(codeSnippets).map((name) => (
                  <button
                    key={name}
                    onClick={() => setActiveSnippetTab(name)}
                    className={`rounded px-3 py-1 font-mono transition cursor-pointer ${
                      activeSnippetTab === name ? "bg-white font-semibold text-[#590907]" : "text-[#45483e]"
                    }`}
                  >
                    {name}
                  </button>
                ))}
              </div>
            }
          />
          <div className="relative mt-4 rounded-lg border border-[#c6c8bb] bg-[#1a1d15] p-5 text-[#f6efe5]">
            <button
              type="button"
              onClick={() => {
                try {
                  if (navigator.clipboard?.writeText) {
                    navigator.clipboard.writeText(codeSnippets[activeSnippetTab]).catch(() => {});
                  }
                } catch {
                  // Fallback
                }
                setCopiedSnippet(true);
                setTimeout(() => setCopiedSnippet(false), 2000);
              }}
              className={`absolute right-4 top-4 flex items-center gap-1.5 rounded px-2.5 py-1 text-xs transition cursor-pointer ${
                copiedSnippet
                  ? "bg-[#1b5e3a] text-white font-semibold"
                  : "bg-[#45483e] hover:bg-[#5e6157] text-[#faf6f0]"
              }`}
            >
              {copiedSnippet ? <Check className="size-3.5 text-[#d8efe0]" /> : <Copy className="size-3.5" />}
              <span>{copiedSnippet ? "Copied!" : "Copy"}</span>
            </button>
            <pre className="overflow-x-auto pr-12 font-mono text-xs leading-5">
              <code>{codeSnippets[activeSnippetTab]}</code>
            </pre>
          </div>
        </Card>
      </PageBody>

      {/* Generate Key Modal */}
      <Dialog
        open={modalOpen && !createdSecret}
        onClose={closeCreationModal}
        icon="249c4.svg"
        title="Generate Ingestion Key"
        subtitle="POST /api/v1/keys"
      >
        <form onSubmit={createKey} className="flex flex-col gap-4">
          <DialogField label="Key Name / Identifier">
            <input
              autoFocus
              required
              maxLength={100}
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
              placeholder="e.g. Production AWS CloudTrail"
              className={dialogInputClass}
            />
          </DialogField>
          <DialogWarning>
            The secret key will be shown <strong className="text-[#5a3800]">only once</strong> after creation. Make sure to copy and store it securely in your secrets vault.
          </DialogWarning>
          {error && <p className="text-sm text-[#93000a]">{error}</p>}
          <DialogFooter>
            <DialogButton type="button" onClick={closeCreationModal}>
              Cancel
            </DialogButton>
            <DialogButton variant="primary" loading={loading}>
              Generate Key
            </DialogButton>
          </DialogFooter>
        </form>
      </Dialog>

      {/* Secret Display Modal (One-time viewing) */}
      <Dialog
        open={modalOpen && Boolean(createdSecret)}
        onClose={closeCreationModal}
        iconTone="green"
        title="API Key Created"
        subtitle={`${createdKeyName} · Active`}
        maxWidth={500}
      >
        <DialogWarning>
          Save this key now. For your security, you will not be able to retrieve this secret again once you close this dialog.
        </DialogWarning>
        <div className="flex flex-col gap-1.5 pt-2">
          <span className="font-ui-medium text-xs text-[#45483e]">Secret Bearer Token</span>
          <div className="flex items-center justify-between gap-3 rounded-lg border border-[#c6c8bb] bg-[#f6efe5] px-4 py-3">
            <code className="font-mono text-xs text-[#1a1d15] select-all truncate">
              {createdSecret}
            </code>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(createdSecret);
                setCopiedSecret(true);
                setTimeout(() => setCopiedSecret(false), 1500);
              }}
              className="font-ui-medium inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-[#590907] px-3 py-1.5 text-xs text-white hover:opacity-95 cursor-pointer"
            >
              {copiedSecret ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
              {copiedSecret ? "Copied" : "Copy Key"}
            </button>
          </div>
        </div>
        <DialogFooter>
          <DialogButton variant="primary" onClick={closeCreationModal}>
            Done, I Have Saved It
          </DialogButton>
        </DialogFooter>
      </Dialog>

      {/* Revoke Key Confirmation Dialog */}
      <Dialog
        open={Boolean(revokeTarget)}
        onClose={() => setRevokeTarget(null)}
        iconTone="red"
        danger
        title="Revoke Ingestion Key"
        subtitle={`DELETE /api/v1/keys/${revokeTarget?.id || ""}`}
      >
        <p className="text-sm leading-5 text-[#45483e]">
          Revoking <strong className="text-[#1a1d15]">{revokeTarget?.name}</strong> immediately blocks any collectors or services using this token with <strong className="text-[#93000a]">401 Unauthorized</strong>.
        </p>
        <DialogFooter>
          <DialogButton onClick={() => setRevokeTarget(null)}>Keep Key</DialogButton>
          <DialogButton variant="danger" loading={revoking} onClick={revokeKey}>
            Revoke Key
          </DialogButton>
        </DialogFooter>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// 6. Log Sources Page
// ---------------------------------------------------------------------------

const collectorTypes = [
  ["SYSLOG", "RFC 5424 Syslog Collector"],
  ["FLUENTBIT", "Fluent Bit HTTP Forwarder"],
  ["FILEBEAT", "Filebeat / Logstash Shipper"],
  ["API", "Direct REST API (Custom App)"],
];

export function SourcesPage() {
  const [sources, setSources] = useState<LogSourceItem[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [values, setValues] = useState({ name: "", collector_type: "SYSLOG", ip_cidr: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadSources = () =>
    api<{ sources: LogSourceItem[] }>("/api/v1/sources")
      .then((res) => setSources(res.sources || []))
      .catch(() => {});

  useEffect(() => {
    loadSources();
  }, []);

  const createSource = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api("/api/v1/sources", {
        method: "POST",
        body: JSON.stringify(values),
      });
      setModalOpen(false);
      setValues({ name: "", collector_type: "SYSLOG", ip_cidr: "" });
      loadSources();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to register source");
    } finally {
      setLoading(false);
    }
  };

  const removeSource = async (id: string) => {
    if (!confirm("Remove this telemetry collector source?")) return;
    try {
      await api(`/api/v1/sources/${id}`, { method: "DELETE" });
      loadSources();
    } catch {
      // Ignored
    }
  };

  return (
    <>
      <Hero
        route="/sources"
        title="Log Sources"
        description="Register and monitor log collectors, firewalls, and application nodes sending telemetry."
        status={
          <span className="rounded-full border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 text-xs font-mono text-[#45483e]">
            ● {sources.length} registered sources
          </span>
        }
        actions={
          <Button onClick={() => setModalOpen(true)}>
            <Plus className="size-4" />
            Add Source
          </Button>
        }
      />
      <PageBody>
        <Card className="overflow-hidden">
          {sources.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[800px] text-left text-sm">
                <thead className="bg-[#f6efe5] border-b border-[#c6c8bb]">
                  <tr>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Source Name</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Collector Type</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">IP / CIDR</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Events Count</th>
                    <th className="px-5 py-3 font-semibold text-[#1a1d15]">Status</th>
                    <th className="px-5 py-3 text-right font-semibold text-[#1a1d15]">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#c6c8bb]/60">
                  {sources.map((s) => (
                    <tr key={s.id} className="hover:bg-[#faf6f0] transition-colors">
                      <td className="px-5 py-4 font-medium text-[#1a1d15]">{s.name}</td>
                      <td className="px-5 py-4">
                        <Badge tone="violet">{s.type || s.collector_type || s.source_type || "SYSLOG"}</Badge>
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-[#45483e]">
                        {s.ip_cidr || "0.0.0.0/0 (Any)"}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-[#1a1d15] font-semibold">
                        {(s.events_count ?? s.event_count ?? 0).toLocaleString()}
                      </td>
                      <td className="px-5 py-4">
                        <Badge tone={s.status?.toLowerCase() === "active" ? "green" : "neutral"}>
                          {s.status?.toUpperCase() || "ACTIVE"}
                        </Badge>
                      </td>
                      <td className="px-5 py-4 text-right">
                        <div className="flex justify-end gap-2">
                          <Link to={`/logs?source=${encodeURIComponent(s.name)}`}>
                            <Button variant="secondary" className="h-8 px-3 text-xs">
                              Logs
                            </Button>
                          </Link>
                          <Button
                            variant="secondary"
                            className="h-8 px-3 text-xs text-[#93000a] hover:bg-[#ffdad5]"
                            onClick={() => removeSource(s.id)}
                          >
                            Remove
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              text="No collector sources configured yet."
              action={
                <Button onClick={() => setModalOpen(true)}>
                  <Plus className="size-4" /> Add Log Source
                </Button>
              }
            />
          )}
        </Card>
      </PageBody>

      {/* Add Source Modal */}
      <Dialog
        open={modalOpen}
        onClose={() => {
          setModalOpen(false);
          setError("");
        }}
        icon="5d706.svg"
        title="Register Log Source"
        subtitle="POST /api/v1/sources"
      >
        <form onSubmit={createSource} className="flex flex-col gap-4">
          <DialogField label="Source Name">
            <input
              autoFocus
              required
              maxLength={100}
              placeholder="e.g. Edge Firewall Cluster"
              value={values.name}
              onChange={(e) => setValues({ ...values, name: e.target.value })}
              className={dialogInputClass}
            />
          </DialogField>

          <DialogField label="Collector Type">
            <select
              value={values.collector_type}
              onChange={(e) => setValues({ ...values, collector_type: e.target.value })}
              className={dialogInputClass}
            >
              {collectorTypes.map(([val, label]) => (
                <option key={val} value={val}>
                  {label}
                </option>
              ))}
            </select>
          </DialogField>

          <DialogField label="Allowed IP / CIDR Block (Optional)">
            <input
              maxLength={50}
              placeholder="e.g. 192.168.1.0/24 or leave empty for any"
              value={values.ip_cidr}
              onChange={(e) => setValues({ ...values, ip_cidr: e.target.value })}
              className={dialogInputClass}
            />
          </DialogField>

          {error && <p className="text-sm text-[#93000a]">{error}</p>}

          <DialogFooter>
            <DialogButton
              type="button"
              onClick={() => {
                setModalOpen(false);
                setError("");
              }}
            >
              Cancel
            </DialogButton>
            <DialogButton variant="primary" loading={loading}>
              Register Source
            </DialogButton>
          </DialogFooter>
        </form>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// 7. Settings Page
// ---------------------------------------------------------------------------

export function SettingsPage() {
  const [profile, setProfile] = useState<{
    id: string;
    full_name?: string;
    email: string;
    is_verified?: boolean;
    created_at?: string;
  } | null>(null);

  const [passwords, setPasswords] = useState({
    current_password: "",
    new_password: "",
    confirm: "",
  });

  const [message, setMessage] = useState("");
  const [isError, setIsError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);

  useEffect(() => {
    api<{
      id: string;
      full_name?: string;
      email: string;
      is_verified?: boolean;
      created_at?: string;
    }>("/auth/me")
      .then(setProfile)
      .catch(() => {});
  }, []);

  const updatePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (passwords.new_password !== passwords.confirm) {
      setIsError(true);
      return setMessage("New passwords do not match.");
    }
    setLoading(true);
    setMessage("");
    setIsError(false);
    try {
      const res = await api<{ message: string }>("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          current_password: passwords.current_password,
          new_password: passwords.new_password,
        }),
      });
      setMessage(res.message || "Password updated successfully.");
      setPasswords({ current_password: "", new_password: "", confirm: "" });
    } catch (err) {
      setIsError(true);
      setMessage(err instanceof Error ? err.message : "Unable to change password");
    } finally {
      setLoading(false);
    }
  };

  const initials = (profile?.full_name || profile?.email || "LM")
    .split(/\s|@/)
    .map((v) => v[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();

  return (
    <>
      <Hero
        route="/settings"
        title="Settings"
        description="Manage workspace credentials, account security, and pipeline defaults."
        status={
          <Badge tone={profile?.is_verified ? "green" : "amber"}>
            {profile?.is_verified ? "Email Verified" : "Unverified"}
          </Badge>
        }
      />
      <PageBody>
        <div className="grid gap-6 xl:grid-cols-2">
          {/* Profile Card */}
          <Card className="p-6">
            <SectionTitle
              title="Workspace Identity"
              description="Authenticated profile synced with LogMorph."
              side={
                <span className="font-ui-medium grid size-10 place-items-center rounded-full border border-[#c6c8bb] bg-[#e8d2b5] text-[#590907] font-semibold">
                  {initials}
                </span>
              }
            />
            <div className="mt-5 space-y-4">
              <Input label="Full Name" value={profile?.full_name || "Enterprise User"} readOnly />
              <Input label="Email Address" value={profile?.email || ""} readOnly />
              <div className="flex justify-between border-t border-[#c6c8bb]/60 pt-3 text-xs text-[#45483e]">
                <span>Account Created</span>
                <span className="font-mono">{formatDate(profile?.created_at)}</span>
              </div>
            </div>
          </Card>

          {/* Change Password Card */}
          <Card className="p-6">
            <SectionTitle
              title="Change Password"
              description="Updating password revokes existing browser sessions."
            />
            <form onSubmit={updatePassword} className="mt-5 space-y-4">
              {message && (
                <div
                  className={`rounded-lg border p-3 text-sm ${
                    isError
                      ? "border-[#93000a]/20 bg-[#ffdad5] text-[#7a0008]"
                      : "border-[#1b5e3a]/20 bg-[#d8efe0] text-[#0b331e]"
                  }`}
                >
                  {message}
                </div>
              )}
              <Input
                label="Current Password"
                type="password"
                required
                value={passwords.current_password}
                onChange={(e) =>
                  setPasswords({ ...passwords, current_password: e.target.value })
                }
              />
              <Input
                label="New Password"
                type="password"
                minLength={8}
                required
                value={passwords.new_password}
                onChange={(e) =>
                  setPasswords({ ...passwords, new_password: e.target.value })
                }
              />
              <Input
                label="Confirm New Password"
                type="password"
                required
                value={passwords.confirm}
                onChange={(e) => setPasswords({ ...passwords, confirm: e.target.value })}
              />
              <Button loading={loading}>Update Password</Button>
            </form>
          </Card>
        </div>

        {/* Danger Zone */}
        <Card className="flex flex-col justify-between gap-5 border-[#93000a]/40 p-6 sm:flex-row sm:items-center">
          <div>
            <h2 className="font-heading-semibold text-lg text-[#93000a]">Workspace Termination</h2>
            <p className="mt-1 text-sm text-[#45483e]">
              Permanently revoke all active ingestion keys and remove telemetry sources.
            </p>
          </div>
          <Button
            variant="danger"
            className="shrink-0"
            onClick={() => setDeleteModalOpen(true)}
          >
            <Trash2 className="size-4" />
            Delete Account
          </Button>
        </Card>
      </PageBody>

      {/* Danger Zone Modal */}
      <Dialog
        open={deleteModalOpen}
        onClose={() => setDeleteModalOpen(false)}
        iconTone="red"
        danger
        title="Delete Workspace Account"
        subtitle={profile?.email || ""}
      >
        <p className="text-sm leading-5 text-[#45483e]">
          This action will permanently disable all ingestion pipelines, purge indexed events, and revoke active Bearer tokens. This action is irreversible.
        </p>
        <DialogFooter>
          <DialogButton onClick={() => setDeleteModalOpen(false)}>Cancel</DialogButton>
          <DialogButton
            variant="danger"
            onClick={() => {
              alert("Contact support at security@logmorph.internal to process workspace deletion.");
              setDeleteModalOpen(false);
            }}
          >
            Confirm Deletion Request
          </DialogButton>
        </DialogFooter>
      </Dialog>
    </>
  );
}
