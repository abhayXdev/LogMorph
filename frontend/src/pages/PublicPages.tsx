import { type FormEvent, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import {
  Check,
  CheckCircle2,
  ChevronRight,
  CircleCheck,
  Copy,
  Eye,
  EyeOff,
  LoaderCircle,
  Mail,
  Zap,
} from "lucide-react";
import {
  api,
  ApiError,
  type UniversalLogEvent,
} from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { Button, Input } from "../components/ui";
import { handleFieldProgression, copyToClipboard } from "../utils/formatters";
import { Logo } from "../components/common/Logo";

export function LandingPage() {
  const samples: Record<string, {
    raw: string;
    latency: string;
    geo: string;
    mitre: string;
    output: UniversalLogEvent;
  }> = {
    Syslog: {
      raw: `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`,
      latency: "Parsed in 4ms · RULE",
      geo: "GeoIP: Mumbai, IN",
      mitre: "MITRE: T1110 - Brute Force",
      output: {
        event_id: "evt_f1e2d3c4",
        timestamp: "2026-10-11T22:14:15Z",
        raw_log: "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        detected_format: "SYSLOG",
        severity: "CRITICAL",
        source: { ip: "192.168.1.50", hostname: "mymachine" },
        security: { user: "lonvick", process_name: "su", auth_action: "LOGIN_FAILED" },
        action: "LOGIN_FAILED",
        parsed_by: "RULE",
        enrichment: {
          geoip: { country: "India", city: "Mumbai" },
          threat_match: false,
          mitre_technique: "T1110 - Brute Force",
        },
      },
    },
    CEF: {
      raw: "CEF:0|Palo Alto|Firewall|9.1|100|TRAFFIC|5|src=192.168.1.10 dst=10.0.0.5 act=ALLOW",
      latency: "Parsed in 3ms · RULE",
      geo: "GeoIP: Ashburn, US",
      mitre: "MITRE: T1046 - Network Discovery",
      output: {
        event_id: "evt_7c44b89e",
        timestamp: "2026-10-11T22:14:15Z",
        raw_log: "CEF:0|Palo Alto|Firewall|9.1|100|TRAFFIC|5|src=192.168.1.10 dst=10.0.0.5 act=ALLOW",
        detected_format: "CEF",
        severity: "NOTICE",
        source: { ip: "192.168.1.10", hostname: "fw-edge-01" },
        destination: { ip: "10.0.0.5" },
        action: "ALLOW",
        parsed_by: "RULE",
        enrichment: {
          geoip: { country: "United States", city: "Ashburn" },
          threat_match: false,
          mitre_technique: "T1046 - Network Discovery",
        },
      },
    },
    LEEF: {
      raw: "LEEF:1.0|IBM|QRadar|7.5|ProcessCreate|src=185.220.101.45\tusrName=admin\tproc=powershell.exe",
      latency: "Parsed in 8ms · TEMPLATE",
      geo: "GeoIP: Frankfurt, DE",
      mitre: "MITRE: T1059.001 - PowerShell",
      output: {
        event_id: "evt_3a19d02f",
        timestamp: "2026-10-11T22:14:15Z",
        raw_log: "LEEF:1.0|IBM|QRadar|7.5|ProcessCreate|src=185.220.101.45\tusrName=admin\tproc=powershell.exe",
        detected_format: "LEEF",
        severity: "WARNING",
        source: { ip: "185.220.101.45" },
        security: { user: "admin", process_name: "powershell.exe" },
        action: "PROCESS_CREATE",
        parsed_by: "TEMPLATE",
        enrichment: {
          geoip: { country: "Germany", city: "Frankfurt" },
          threat_match: true,
          mitre_technique: "T1059.001 - PowerShell",
        },
      },
    },
    JSON: {
      raw: `{"timestamp":"2026-09-23T10:00:00Z","level":"ERROR","msg":"Connection timeout to primary vault","service":"auth-service"}`,
      latency: "Parsed in 5ms · TEMPLATE",
      geo: "GeoIP: Internal VPC",
      mitre: "MITRE: None Detected",
      output: {
        event_id: "evt_5e01a77c",
        timestamp: "2026-09-23T10:00:00Z",
        raw_log: `{"timestamp":"2026-09-23T10:00:00Z","level":"ERROR","msg":"Connection timeout to primary vault","service":"auth-service"}`,
        detected_format: "JSON",
        severity: "ERROR",
        source: { hostname: "auth-service" },
        action: "CONNECTION_TIMEOUT",
        parsed_by: "TEMPLATE",
        enrichment: {
          geoip: null,
          threat_match: false,
          mitre_technique: null,
        },
      },
    },
  };

  const snippets: Record<string, string> = {
    cURL: `curl -X POST https://logmorph.onrender.com/api/v1/ingest \\
  -H "Authorization: Bearer lm_live_YOUR_KEY_HERE" \\
  -H "Content-Type: application/json" \\
  -d '{"raw_log":"<34>Oct 11 22:14:15 host sshd: login failed","source":"production-firewall"}'`,
    Python: `import requests

requests.post(
  "https://logmorph.onrender.com/api/v1/ingest",
  headers={"Authorization": "Bearer lm_live_YOUR_KEY_HERE"},
  json={"raw_log": raw_line, "source": "billing-api"}
)`,
    "Node.js": `await fetch("https://logmorph.onrender.com/api/v1/ingest", {
  method: "POST",
  headers: {
    "Authorization": "Bearer lm_live_YOUR_KEY_HERE",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ raw_log, source: "edge-gateway" })
});`,
    Go: `req, _ := http.NewRequest("POST", "https://logmorph.onrender.com/api/v1/ingest", payload)
req.Header.Set("Authorization", "Bearer lm_live_YOUR_KEY_HERE")
req.Header.Set("Content-Type", "application/json")
resp, err := http.DefaultClient.Do(req)`,
    Fluentbit: `[OUTPUT]
    Name http
    Match *
    Host logmorph.onrender.com
    URI /api/v1/ingest
    Header Authorization Bearer lm_live_YOUR_KEY_HERE
    tls On`,
  };

  const [sample, setSample] = useState<string>("Syslog");
  const [raw, setRaw] = useState(samples.Syslog.raw);
  const [parsed, setParsed] = useState<unknown>(samples.Syslog.output);
  const [latency, setLatency] = useState(samples.Syslog.latency);
  const [loading, setLoading] = useState(false);
  const [language, setLanguage] = useState("cURL");
  const [copied, setCopied] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  function chooseSample(name: string) {
    const next = samples[name];
    if (!next) return;
    setSample(name);
    setRaw(next.raw);
    setParsed(next.output);
    setLatency(next.latency);
  }

  async function parse() {
    setLoading(true);
    const started = performance.now();
    try {
      const res = await api<UniversalLogEvent>("/api/v1/sandbox/parse", {
        method: "POST",
        body: JSON.stringify({ raw_log: raw }),
      });
      setParsed(res);
      const elapsed = Math.max(1, Math.round(performance.now() - started));
      setLatency(`Parsed in ${elapsed}ms · ${res.parsed_by || "PARSED"}`);
    } catch {
      // Graceful fallback to pre-computed output if API is offline
      setParsed(samples[sample]?.output || {});
      setLatency(samples[sample]?.latency || "Parsed locally");
    } finally {
      setLoading(false);
    }
  }

  const architecture = [
    {
      asset: "/assets/eebde.svg",
      tier: "Tier 1 · 70.2%",
      code: "RULE",
      title: "Rule / Regex Fast-Path",
      text: "Pre-compiled regex engines for Syslog, Apache/Nginx CLF, CEF, and LEEF parse telemetry at sub-millisecond speeds.",
      note: "Zero-cost compute path",
      tone: "success",
    },
    {
      asset: "/assets/e7eca.svg",
      tier: "Tier 2 · 20.0%",
      code: "TEMPLATE",
      title: "Drain3 Tree Clustering",
      text: "Online log-tree clustering discovers recurring structural message templates and automatically extracts variable parameters.",
      note: "GeoIP & Threat Match",
      tone: "sage",
    },
    {
      asset: "/assets/19cf8.svg",
      tier: "Tier 3 · 7.6%",
      code: "LLM",
      title: "NVIDIA NIM Inference",
      text: "Unstructured or unknown logs fall back to NVIDIA NIM schema inference with automatic MITRE ATT&CK technique classification.",
      note: "MITRE ATT&CK Mapping",
      tone: "warning",
    },
  ];

  const capabilities = [
    {
      asset: "/assets/01f23.svg",
      title: "Analytics Dashboard",
      route: "/dashboard",
      text: "Monitor real-time event rates, active collector nodes, parse latency, and threat IOC alerts across all connected environments.",
    },
    {
      asset: "/assets/780a6.svg",
      title: "Log Explorer & Inspector",
      route: "/logs",
      text: "Full-text search, multi-field filtering, and side-by-side inspection between raw log payloads and normalized UniversalLogEvent JSON.",
    },
    {
      asset: "/assets/a1820.svg",
      title: "Sandbox & Key Management",
      route: "/sandbox · /keys",
      text: "Test heterogeneous payloads without persistence and mint one-time cryptographically hashed Bearer ingestion keys with instant revocation.",
    },
    {
      asset: "/assets/f3e63.svg",
      title: "Log Sources & Collectors",
      route: "/sources",
      text: "Register collectors, track per-source event counts, monitor heartbeat timestamps, and isolate telemetry by IP CIDR block.",
    },
  ];

  return (
    <div className="reference-landing min-h-screen bg-[#faf6f0] text-[#1a1d15]">
      {/* Top Navigation */}
      <header className="sticky top-0 z-40 border-b border-[#c6c8bb] bg-[#faf6f0]/95 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-6">
          <div className="flex items-center gap-3">
            <Logo light />
            <span className="hidden items-center gap-1.5 rounded-full border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 font-mono text-[11px] text-[#45483e] sm:inline-flex">
              <span className="size-1.5 rounded-full bg-[#1b5e3a] animate-pulse" />
              API Live
            </span>
          </div>
          <nav className="hidden items-center gap-6 text-sm font-medium text-[#45483e] md:flex">
            <a href="#demo" className="hover:text-[#590907] transition">Live Parser</a>
            <a href="#architecture" className="hover:text-[#590907] transition">3-Tier Cascade</a>
            <a href="#platform" className="hover:text-[#590907] transition">Command Center</a>
            <a href="#integrations" className="hover:text-[#590907] transition">Ingest API</a>
          </nav>
          <div className="flex items-center gap-2">
            <Link to="/login">
              <Button variant="ghost">Log In</Button>
            </Link>
            <Link to="/signup">
              <Button>Get Started</Button>
            </Link>
          </div>
        </div>
      </header>

      <main>
        {/* Hero & Interactive Parser */}
        <section id="demo" className="border-b border-[#c6c8bb] py-12 sm:py-16">
          <div className="mx-auto flex max-w-7xl flex-col gap-8 px-6">
            <div className="max-w-3xl space-y-4">
              <div className="inline-flex items-center gap-2 rounded-full border border-[#c6c8bb] bg-[#e8d2b5] px-3 py-1 font-mono text-xs text-[#590907]">
                <span>FASTAPI · KAFKA · REDIS · NVIDIA NIM</span>
              </div>
              <h1 className="text-[32px] font-bold leading-[1.12] tracking-[-.04em] sm:text-[50px] text-[#1a1d15]">
                Normalize raw security logs into structured ULS events.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-[#45483e]">
                LogMorph routes Syslog, CEF, LEEF, CLF, and JSON streams through a 3-tier cascade—Rule/Regex, Drain3 Templates, and NVIDIA NIM—with automatic GeoIP, threat intel, and MITRE ATT&CK enrichment.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <Link to="/signup">
                  <Button className="h-11 px-6 shadow-sm">
                    <img src="/assets/6d852.svg" alt="" className="size-4 mr-1" />
                    Get Started Free
                  </Button>
                </Link>
                <a href="#integrations">
                  <Button variant="secondary" className="h-11 px-6">
                    View Ingest API
                  </Button>
                </a>
              </div>
            </div>

            {/* Live Interactive Parser Box */}
            <div className="overflow-hidden rounded-xl border border-[#c6c8bb] bg-white shadow-sm">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#c6c8bb] bg-[#e8d2b5] px-5 py-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs font-semibold text-[#1a1d15]">Sample:</span>
                  <div className="flex rounded-md border border-[#c6c8bb] bg-[#f6efe5] p-1">
                    {Object.keys(samples).map((name) => (
                      <button
                        key={name}
                        onClick={() => chooseSample(name)}
                        className={`rounded px-3 py-1 text-xs font-medium transition cursor-pointer ${
                          sample === name
                            ? "bg-[#590907] text-white shadow-xs"
                            : "text-[#45483e] hover:text-[#1a1d15]"
                        }`}
                      >
                        {name}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-[#d8efe0] border border-[#1b5e3a]/20 px-2.5 py-1 font-mono text-[11px] text-[#0b331e]">
                    <span className="size-1.5 rounded-full bg-[#1b5e3a]" />
                    {latency}
                  </span>
                  <button
                    onClick={parse}
                    disabled={loading}
                    className="inline-flex items-center gap-1.5 rounded-md bg-[#590907] px-3.5 py-1.5 text-xs font-semibold text-white hover:opacity-95 disabled:opacity-60 transition cursor-pointer"
                  >
                    {loading ? (
                      <LoaderCircle className="size-3.5 animate-spin" />
                    ) : (
                      <Zap className="size-3.5" />
                    )}
                    {loading ? "Parsing…" : "Parse Log"}
                  </button>
                </div>
              </div>

              <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-[#c6c8bb]">
                {/* Raw Input Column */}
                <div className="space-y-3 p-6">
                  <div className="flex justify-between text-xs font-medium text-[#45483e]">
                    <span>Raw Log Input</span>
                    <span className="font-mono text-[#590907] font-semibold">{sample.toUpperCase()}</span>
                  </div>
                  <textarea
                    value={raw}
                    onChange={(e) => setRaw(e.target.value)}
                    rows={11}
                    className="w-full resize-none rounded-md border border-[#c6c8bb] bg-[#f6efe5] p-4 font-mono text-[13px] leading-5 text-[#1a1d15] outline-none focus:border-[#590907] focus:bg-white transition"
                  />
                  <div className="flex flex-wrap gap-2 pt-1">
                    <span className="rounded-full bg-[#e2e4d6] border border-[#c6c8bb]/60 px-2.5 py-1 font-mono text-[11px] text-[#34372f]">
                      {samples[sample]?.geo}
                    </span>
                    <span className="rounded-full bg-[#ffdad5] border border-[#93000a]/20 px-2.5 py-1 font-mono text-[11px] text-[#7a0008]">
                      {samples[sample]?.mitre}
                    </span>
                  </div>
                </div>

                {/* Parsed Output Column */}
                <div className="flex min-h-[380px] flex-col gap-3 bg-[#1a1d15] p-6 text-[#f6efe5]">
                  <div className="flex items-center justify-between border-b border-white/10 pb-3">
                    <span className="text-xs font-mono font-medium text-[#e8d2b5]">
                      UniversalLogEvent (ULS Schema)
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        copyToClipboard(JSON.stringify(parsed, null, 2), () => {
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                        });
                      }}
                      className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs transition cursor-pointer ${
                        copied
                          ? "bg-[#1b5e3a] text-[#d8efe0] font-semibold"
                          : "bg-[#45483e] hover:bg-[#5e6157] text-[#faf6f0]"
                      }`}
                    >
                      {copied ? <Check className="size-3 text-[#d8efe0]" /> : <Copy className="size-3" />}
                      <span>{copied ? "Copied!" : "Copy JSON"}</span>
                    </button>
                  </div>
                  <pre className="overflow-auto whitespace-pre-wrap font-mono text-[12px] leading-5 text-[#f6efe5] flex-1 max-h-[320px]">
                    <code>{JSON.stringify(parsed, null, 2)}</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Supported Formats Banner */}
        <section className="border-b border-[#c6c8bb] bg-[#e8d2b5] py-4">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6">
            <span className="text-xs font-semibold text-[#1a1d15] tracking-wider uppercase">
              Supported Telemetry Standards
            </span>
            <div className="flex flex-wrap gap-2">
              {["RFC 5424 SYSLOG", "JSON ARTIFACTS", "ARCSIGHT CEF", "IBM LEEF", "APACHE/NGINX CLF", "UNSTRUCTURED"].map(
                (format, index) => (
                  <span
                    key={format}
                    className={`rounded-md border border-[#c6c8bb] bg-white px-3 py-1 font-mono text-xs font-medium ${
                      index === 0 ? "text-[#590907] font-semibold" : "text-[#45483e]"
                    }`}
                  >
                    {format}
                  </span>
                )
              )}
            </div>
          </div>
        </section>

        {/* Architecture 3-Tier Cascade */}
        <section id="architecture" className="border-b border-[#c6c8bb] py-16">
          <div className="mx-auto max-w-7xl space-y-8 px-6">
            <div className="max-w-2xl">
              <h2 className="text-3xl font-bold tracking-tight sm:text-[38px] text-[#1a1d15]">
                Three-tier parsing cascade.
              </h2>
              <p className="mt-3 text-base leading-7 text-[#45483e]">
                Incoming telemetry falls through deterministic regex rules first, then Drain3 log-template clustering, and finally NVIDIA NIM inference only when necessary.
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-3">
              {architecture.map((item) => (
                <article
                  key={item.title}
                  className="reference-card flex min-h-64 flex-col justify-between rounded-lg border border-[#c6c8bb] bg-white p-6 shadow-xs"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`rounded-full px-2.5 py-1 font-mono text-[11px] font-medium ${
                          item.tone === "success"
                            ? "bg-[#d8efe0] text-[#0b331e] border border-[#1b5e3a]/20"
                            : item.tone === "warning"
                            ? "bg-[#f6dfc2] text-[#5a3800] border border-[#855300]/20"
                            : "bg-[#e2e4d6] text-[#34372f] border border-[#76786d]/20"
                        }`}
                      >
                        {item.tier}
                      </span>
                      <span className="font-mono text-[11px] text-[#590907] font-semibold">
                        {item.code}
                      </span>
                    </div>
                    <h3 className="mt-4 text-lg font-semibold text-[#1a1d15]">{item.title}</h3>
                    <p className="mt-2 text-sm leading-6 text-[#45483e]">{item.text}</p>
                  </div>
                  <div className="mt-6 flex items-center justify-between border-t border-[#c6c8bb] pt-4 text-xs text-[#45483e]">
                    <span className="font-mono">{item.note}</span>
                    <img src={item.asset} alt="" className="size-5" />
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* Command Center Feature Grid */}
        <section id="platform" className="border-b border-[#c6c8bb] bg-[#f6efe5] py-16">
          <div className="mx-auto max-w-7xl space-y-8 px-6">
            <div className="max-w-2xl">
              <h2 className="text-3xl font-bold tracking-tight sm:text-[38px] text-[#1a1d15]">
                Everything inside the LogMorph Command Center.
              </h2>
              <p className="mt-3 text-base leading-7 text-[#45483e]">
                Engineered with FastAPI, Apache Kafka, and Redis to transform raw streams into searchable, enriched intelligence.
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-2">
              {capabilities.map(({ asset, title, route, text }) => (
                <article
                  key={title}
                  className="reference-card rounded-lg border border-[#c6c8bb] bg-white p-6 shadow-xs"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <span className="grid size-10 place-items-center rounded-lg bg-[#e8d2b5] border border-[#c6c8bb]/60">
                        <img src={asset} alt="" className="size-5" />
                      </span>
                      <h3 className="font-semibold text-lg text-[#1a1d15]">{title}</h3>
                    </div>
                    <span className="font-mono text-xs text-[#76786d]">{route}</span>
                  </div>
                  <p className="mt-3 text-sm leading-6 text-[#45483e]">{text}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* Integration Code Snippets */}
        <section id="integrations" className="py-16">
          <div className="mx-auto grid max-w-7xl items-start gap-8 px-6 lg:grid-cols-12">
            <div className="space-y-4 lg:col-span-5">
              <div className="inline-flex rounded-full border border-[#c6c8bb] bg-[#e8d2b5] px-3 py-1 font-mono text-xs text-[#590907]">
                HTTPS INGESTION API
              </div>
              <h2 className="text-3xl font-bold tracking-tight sm:text-[38px] text-[#1a1d15]">
                Ingest from any collector with one API key.
              </h2>
              <p className="text-base leading-7 text-[#45483e]">
                Ship single logs to <code className="font-mono text-[#590907] font-semibold bg-[#efe6da] px-1 py-0.5 rounded">/api/v1/ingest</code> or batches up to 500 events to <code className="font-mono text-[#590907] font-semibold bg-[#efe6da] px-1 py-0.5 rounded">/api/v1/ingest/batch</code> with gzip transit.
              </p>
              <ul className="space-y-2.5 pt-2 text-sm text-[#45483e]">
                <li className="flex items-center gap-2">
                  <CircleCheck className="size-4 text-[#590907] shrink-0" />
                  <span>Bearer token authentication (<code className="font-mono text-xs text-[#590907]">lm_live_...</code>)</span>
                </li>
                <li className="flex items-center gap-2">
                  <CircleCheck className="size-4 text-[#590907] shrink-0" />
                  <span>Content-Encoding: gzip automatic decompression</span>
                </li>
                <li className="flex items-center gap-2">
                  <CircleCheck className="size-4 text-[#590907] shrink-0" />
                  <span>Automatic sub-second deduplication in Redis</span>
                </li>
              </ul>
            </div>

            <div className="overflow-hidden rounded-xl border border-[#c6c8bb] bg-[#1a1d15] shadow-sm lg:col-span-7">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#c6c8bb] bg-[#e8d2b5] p-2.5">
                <div className="flex flex-wrap gap-1">
                  {Object.keys(snippets).map((name) => (
                    <button
                      key={name}
                      onClick={() => setLanguage(name)}
                      className={`rounded px-3 py-1 font-mono text-xs font-medium transition cursor-pointer ${
                        language === name
                          ? "bg-[#590907] text-white shadow-xs"
                          : "text-[#45483e] hover:bg-white/60"
                      }`}
                    >
                      {name}
                    </button>
                  ))}
                </div>
                <button
                  type="button"
                  onClick={() => {
                    copyToClipboard(snippets[language], () => {
                      setCopiedSnippet(true);
                      setTimeout(() => setCopiedSnippet(false), 2000);
                    });
                  }}
                  className={`inline-flex items-center gap-1.5 rounded border px-3 py-1 text-xs font-medium transition cursor-pointer ${
                    copiedSnippet
                      ? "border-[#1b5e3a] bg-[#d8efe0] text-[#0b331e]"
                      : "border-[#c6c8bb] bg-white text-[#1a1d15] hover:bg-[#f6efe5]"
                  }`}
                >
                  {copiedSnippet ? (
                    <Check className="size-3.5 text-[#1b5e3a]" />
                  ) : (
                    <Copy className="size-3.5" />
                  )}
                  <span>{copiedSnippet ? "Copied!" : "Copy Snippet"}</span>
                </button>
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap p-6 font-mono text-[12px] leading-6 text-[#f6efe5]">
                <code>{snippets[language]}</code>
              </pre>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#c6c8bb] bg-[#f6efe5] py-8">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6">
          <div className="flex items-center gap-3">
            <Logo light />
            <span className="text-sm text-[#45483e]">
              · Enterprise Security Telemetry Pipeline
            </span>
          </div>
          <div className="flex gap-6 text-sm font-medium text-[#45483e]">
            <Link to="/login" className="hover:text-[#590907] transition">Log In</Link>
            <Link to="/signup" className="hover:text-[#590907] transition">Get Started</Link>
            <a href="https://logmorph.onrender.com/docs" target="_blank" rel="noreferrer" className="hover:text-[#590907] transition">
              OpenAPI Docs
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Auth Pages Shell & Shared Components
// ---------------------------------------------------------------------------

type AuthKind = "login" | "signup" | "verify" | "forgot" | "reset";

const authAside: Record<
  AuthKind,
  {
    eyebrow: string;
    title: string;
    text: string;
    features: [string, string, string][];
    footer: string;
  }
> = {
  login: {
    eyebrow: "3-Tier Normalization Cascade",
    title: "One unified schema for every log stream.",
    text: "Ingest Syslog, CEF, LEEF, or raw JSON. LogMorph normalizes, deduplicates, and enriches every event before it hits your dashboard.",
    footer: "Rule/Regex · Drain3 · NVIDIA NIM",
    features: [
      [
        "/assets/3f07a.svg",
        "Multi-Format Ingestion",
        "Stream single events or high-volume batches over HTTPS with Bearer API key authentication.",
      ],
      [
        "/assets/a7931.svg",
        "Rule, Drain3 & AI Cascade",
        "Deterministic regex rules handle known streams first, falling back to Drain3 templates and NVIDIA NIM.",
      ],
      [
        "/assets/ca27d.svg",
        "Enriched ULS Output",
        "Every event lands with normalized severity, GeoIP context, and MITRE ATT&CK mapping.",
      ],
    ],
  },
  signup: {
    eyebrow: "Ready in 60 Seconds",
    title: "Ship raw logs, query structured security telemetry.",
    text: "Every new workspace includes an isolated ingestion pipeline, Bearer API keys, and the live Sandbox parser.",
    footer: "Free Developer Tier",
    features: [
      [
        "/assets/4fba6.svg",
        "Instant API Keys",
        "Generate scoped Bearer tokens for firewalls, Kubernetes clusters, and cloud audit streams.",
      ],
      [
        "/assets/30e4d.svg",
        "Interactive Sandbox",
        "Test Syslog, CEF, LEEF, and unstructured logs against the 3-tier cascade before deploying shippers.",
      ],
      [
        "/assets/ca27d.svg",
        "MITRE ATT&CK Enrichment",
        "Automatic GeoIP lookup and threat technique tagging on every normalized UniversalLogEvent.",
      ],
    ],
  },
  verify: {
    eyebrow: "First 3 Minutes in LogMorph",
    title: "Everything unlocked in your Command Center.",
    text: "Once your email is confirmed, follow these three quick steps to start normalizing live telemetry.",
    footer: "Account Ready",
    features: [
      [
        "/assets/4fba6.svg",
        "1. Generate an Ingestion Key",
        "Create a Bearer lm_live_* token to authenticate your firewalls and app shippers.",
      ],
      [
        "/assets/ff039.svg",
        "2. Register a Log Source",
        "Group incoming events by collector node for instant filtering.",
      ],
      [
        "/assets/30e4d.svg",
        "3. Test in the Live Sandbox",
        "Paste any raw log line and inspect normalized ULS JSON in milliseconds.",
      ],
    ],
  },
  forgot: {
    eyebrow: "Zero-Trust Recovery Flow",
    title: "How LogMorph protects your workspace credentials.",
    text: "Password resets use short-lived cryptographic tokens so your ingestion keys and telemetry history stay isolated.",
    footer: "429 Cooldown Protected",
    features: [
      [
        "/assets/b4eb3.svg",
        "Single-Use Cryptographic Token",
        "Every recovery link expires automatically after use and cannot be replayed.",
      ],
      [
        "/assets/17d7b.svg",
        "Enumeration Protection",
        "The endpoint always returns a neutral confirmation so account emails remain private.",
      ],
      [
        "/assets/80233.svg",
        "Session Revocation",
        "Completing a reset invalidates older JWT sessions while keeping API keys online.",
      ],
    ],
  },
  reset: {
    eyebrow: "Credential Hygiene",
    title: "Stronger passwords keep your ingestion pipeline safe.",
    text: "LogMorph enforces complexity checks before updating your account hash and immediately revokes older JWT sessions.",
    footer: "/reset-password?token=···",
    features: [
      [
        "/assets/1d142.svg",
        "8+ Characters & Mixed Case",
        "Combine uppercase, lowercase, and at least one number to reach Strong status.",
      ],
      [
        "/assets/9f4bc.svg",
        "Automatic Session Rotation",
        "Existing browser sessions are signed out while active ingestion keys remain uninterrupted.",
      ],
      [
        "/assets/ca27d.svg",
        "Protected Account Hash",
        "Password updates use secure hashing and short-lived reset credentials.",
      ],
    ],
  },
};

function AuthFrame({
  kind,
  title,
  subtitle,
  children,
  footer,
}: {
  kind: AuthKind;
  title: string;
  subtitle: string;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  const aside = authAside[kind];
  const back =
    kind === "login" || kind === "signup" ? "Back to LogMorph" : "Back to Sign In";
  const endpoint =
    kind === "login"
      ? "API Live"
      : kind === "signup"
      ? "API Live"
      : `POST /auth/${kind === "verify" ? "verify-email" : kind === "forgot" ? "forgot-password" : "reset-password"}`;

  return (
    <div className="auth-light grid min-h-screen bg-[#faf6f0] lg:grid-cols-12">
      {/* Form Column */}
      <section className="flex min-h-screen flex-col border-[#c6c8bb] bg-white px-6 py-8 lg:col-span-5 lg:border-r lg:px-12">
        <div className="flex items-center justify-between text-sm">
          <Link
            to={kind === "login" || kind === "signup" ? "/" : "/login"}
            className="flex items-center gap-2 font-ui-medium text-[#45483e] hover:text-[#590907] transition"
          >
            <img src="/assets/c61e9.svg" alt="" className="size-4" />
            <span>{back}</span>
          </Link>
          <span className="flex items-center gap-1.5 rounded-full border border-[#c6c8bb] bg-[#f6efe5] px-2.5 py-1 font-mono-medium text-xs text-[#45483e]">
            <span className="size-1.5 rounded-full bg-[#1b5e3a] animate-pulse" />
            {endpoint}
          </span>
        </div>

        <div className="flex flex-1 items-center py-10">
          <div className="mx-auto w-full max-w-[448px]">
            <div className="mb-4">
              <Logo light />
            </div>
            <h1 className="font-heading-semibold text-[28px] leading-[34px] tracking-[-.25px] text-[#1a1d15]">
              {title}
            </h1>
            <p className="mt-1 text-sm leading-5 text-[#45483e]">{subtitle}</p>
            <div className="mt-8">{children}</div>
            <div className="mt-6 text-sm text-[#45483e]">{footer}</div>
          </div>
        </div>

        <div className="flex items-center justify-between text-xs text-[#45483e] border-t border-[#c6c8bb] pt-4">
          <span>
            {kind === "login"
              ? "JWT Bearer Session"
              : kind === "signup"
              ? "Email Verification Required"
              : kind === "forgot"
              ? "Account Recovery"
              : kind === "reset"
              ? "Token Verified"
              : "LogMorph Account Security"}
          </span>
          <span className="font-mono-medium text-[#76786d]">{endpoint}</span>
        </div>
      </section>

      {/* Decorative Aside Column */}
      <aside className="auth-aside hidden min-h-screen flex-col justify-between bg-[#f6efe5] p-16 lg:col-span-7 lg:flex">
        <div className="my-auto mx-auto w-full max-w-lg">
          <span className="inline-flex rounded-full border border-[#c6c8bb] bg-[#e8d2b5] px-3 py-1 font-mono-medium text-xs text-[#590907]">
            {aside.eyebrow}
          </span>
          <h2 className="mt-3 font-heading-semibold text-[28px] leading-[34px] tracking-[-.25px] text-[#1a1d15]">
            {aside.title}
          </h2>
          <p className="mt-2 text-sm leading-5 text-[#45483e]">{aside.text}</p>
          <div className="mt-8 space-y-4">
            {aside.features.map(([asset, heading, text]) => (
              <div
                key={heading}
                className="flex gap-4 rounded-xl border border-[#c6c8bb] bg-white p-4 shadow-xs"
              >
                <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-[#e8d2b5]">
                  <img src={asset} alt="" className="size-5" />
                </span>
                <div>
                  <h3 className="font-heading-semibold text-base leading-[22px] text-[#1a1d15]">
                    {heading}
                  </h3>
                  <p className="mt-1 text-sm leading-5 text-[#45483e]">{text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="mx-auto flex w-full max-w-lg items-center justify-between border-t border-[#c6c8bb] pt-4 text-xs text-[#45483e]">
          <span>FastAPI · Kafka · Redis Telemetry</span>
          <span className="font-mono-medium">{aside.footer}</span>
        </div>
      </aside>
    </div>
  );
}

function ErrorMessage({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-[#93000a]/30 bg-[#ffdad5] p-3 text-sm text-[#7a0008]">
      {text}
    </div>
  );
}

function PasswordField({
  value,
  onChange,
  label = "Password",
  autoComplete = "current-password",
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
  autoComplete?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <Input
        label={label}
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        required
        className="pr-11"
      />
      <button
        type="button"
        onClick={() => setShow(!show)}
        aria-label={show ? "Hide password" : "Show password"}
        className="absolute bottom-3 right-3 text-[#76786d] hover:text-[#1a1d15] cursor-pointer"
      >
        {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </button>
    </div>
  );
}

function strength(password: string) {
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score++;
  return score;
}

function StrengthMeter({ password }: { password: string }) {
  const score = strength(password);
  const colors = ["bg-[#c6c8bb]", "bg-[#93000a]", "bg-[#855300]", "bg-[#1b5e3a]"];
  const checks = [
    ["8+ chars", password.length >= 8],
    ["Uppercase", /[A-Z]/.test(password)],
    ["Lowercase", /[a-z]/.test(password)],
    ["Number", /\d/.test(password)],
  ] as const;

  return (
    <div className="pt-2">
      <div className="grid grid-cols-3 gap-1">
        {[1, 2, 3].map((n) => (
          <div
            key={n}
            className={`h-1.5 rounded-full transition-all ${
              n <= score ? colors[score] : "bg-[#e2e4d6]"
            }`}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {checks.map(([label, met]) => (
          <span
            key={label}
            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${
              met
                ? "border-[#1b5e3a]/20 bg-[#d8efe0] text-[#0b331e]"
                : "border-[#c6c8bb] bg-[#f6efe5] text-[#45483e]"
            }`}
          >
            <span
              className={`size-1.5 rounded-full ${
                met ? "bg-[#1b5e3a]" : "bg-[#76786d]"
              }`}
            />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

export function LoginPage() {
  const navigate = useNavigate();
  const { login, isAuthenticated } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [unverified, setUnverified] = useState(false);
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard", { replace: true });
    }
  }, [isAuthenticated, navigate]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setUnverified(false);
    try {
      await login(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to log in");
      if (err instanceof ApiError && (err.status === 403 || err.status === 401)) {
        if (err.message.toLowerCase().includes("verify") || err.message.toLowerCase().includes("verified")) {
          setUnverified(true);
        }
      }
    } finally {
      setLoading(false);
    }
  }

  async function resend() {
    try {
      await api("/auth/resend-verification", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      setSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not resend verification email");
    }
  }

  return (
    <AuthFrame
      kind="login"
      title="Sign in to your workspace"
      subtitle="Enter your credentials to access your telemetry dashboard, log explorer, and API keys."
      footer={
        <div className="flex justify-between border-t border-[#c6c8bb] pt-4">
          <span>New to LogMorph?</span>
          <Link className="font-ui-medium text-[#590907] font-semibold hover:underline" to="/signup">
            Create an account
          </Link>
        </div>
      }
    >
      <form onSubmit={submit} onKeyDown={handleFieldProgression} className="space-y-4">
        {error && <ErrorMessage text={error} />}
        {unverified && (
          <button
            type="button"
            onClick={resend}
            className="w-full rounded-lg border border-[#855300]/20 bg-[#f6dfc2] p-3 text-left text-sm text-[#5a3800] hover:opacity-90 cursor-pointer"
          >
            {sent
              ? "Verification email sent. Check your inbox."
              : "Email not verified. Click to resend verification email."}
          </button>
        )}
        <Input
          label="Email address"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
          required
          placeholder="admin@company.com"
        />
        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="font-ui-medium text-xs text-[#45483e]">Password</span>
            <Link
              to="/forgot-password"
              className="font-ui-medium text-xs text-[#590907] hover:underline"
            >
              Forgot password?
            </Link>
          </div>
          <PasswordField value={password} onChange={setPassword} label="" />
        </div>
        <Button className="w-full mt-2" loading={loading}>
          Log In
        </Button>
      </form>
    </AuthFrame>
  );
}

export function SignupPage() {
  const [values, setValues] = useState({ full_name: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [copiedEmail, setCopiedEmail] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (values.password !== values.confirm) {
      return setError("Passwords do not match");
    }
    setLoading(true);
    setError("");
    try {
      await api("/auth/signup", {
        method: "POST",
        body: JSON.stringify({
          full_name: values.full_name,
          email: values.email,
          password: values.password,
        }),
      });
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create account");
    } finally {
      setLoading(false);
    }
  }

  if (done) {
    return (
      <AuthFrame
        kind="signup"
        title="Check your inbox"
        subtitle="Your verification link is on its way."
        footer={
          <Link className="font-ui-medium text-[#590907] font-semibold hover:underline" to="/login">
            Back to login
          </Link>
        }
      >
        <div className="rounded-lg border border-[#c6c8bb] bg-[#f6efe5] p-5">
          <Mail className="size-6 text-[#590907]" />
          <p className="mt-3 text-sm leading-6 text-[#45483e]">
            We sent a verification email to <strong className="text-[#1a1d15]">{values.email}</strong>.
            Please verify your email address to unlock full ingestion API keys.
          </p>
          <div className="mt-4 flex items-center justify-between gap-3 rounded-lg border border-[#c6c8bb] bg-white p-2.5">
            <span className="font-mono text-xs text-[#1a1d15] truncate">{values.email}</span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(values.email);
                setCopiedEmail(true);
                setTimeout(() => setCopiedEmail(false), 2000);
              }}
              className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition cursor-pointer ${
                copiedEmail
                  ? "bg-[#d8efe0] text-[#0b331e] font-semibold"
                  : "bg-[#f6efe5] text-[#590907] hover:bg-[#efe6da]"
              }`}
            >
              {copiedEmail ? <Check className="size-3 text-[#1b5e3a]" /> : <Copy className="size-3" />}
              <span>{copiedEmail ? "Copied!" : "Copy"}</span>
            </button>
          </div>
        </div>
      </AuthFrame>
    );
  }

  return (
    <AuthFrame
      kind="signup"
      title="Create your workspace"
      subtitle="Start normalizing Syslog, CEF, and JSON logs in minutes with your free developer account."
      footer={
        <div className="flex justify-between border-t border-[#c6c8bb] pt-4">
          <span>Already have an account?</span>
          <Link className="font-ui-medium text-[#590907] font-semibold hover:underline" to="/login">
            Log in
          </Link>
        </div>
      }
    >
      <form onSubmit={submit} onKeyDown={handleFieldProgression} className="space-y-4">
        {error && <ErrorMessage text={error} />}
        <Input
          label="Full Name"
          value={values.full_name}
          onChange={(e) => setValues({ ...values, full_name: e.target.value })}
          required
          placeholder="Security Engineer"
        />
        <Input
          label="Email address"
          type="email"
          value={values.email}
          onChange={(e) => setValues({ ...values, email: e.target.value })}
          required
          placeholder="secops@company.com"
        />
        <div>
          <PasswordField
            label="Password"
            value={values.password}
            onChange={(password) => setValues({ ...values, password })}
            autoComplete="new-password"
          />
          <StrengthMeter password={values.password} />
        </div>
        <PasswordField
          label="Confirm Password"
          value={values.confirm}
          onChange={(confirm) => setValues({ ...values, confirm })}
          autoComplete="new-password"
        />
        {values.confirm && (
          <p
            className={`text-xs ${
              values.password === values.confirm ? "text-[#1b5e3a]" : "text-[#93000a]"
            }`}
          >
            {values.password === values.confirm ? "Passwords match" : "Passwords do not match"}
          </p>
        )}
        <Button
          className="mt-2 w-full"
          loading={loading}
          disabled={strength(values.password) < 1 || values.password !== values.confirm}
        >
          Create Account
        </Button>
      </form>
    </AuthFrame>
  );
}

export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const [state, setState] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");
  const [cooldown, setCooldown] = useState(60);
  const [email, setEmail] = useState("");

  useEffect(() => {
    if (!token) {
      setState("error");
      setMessage("This verification link is missing a security token.");
      return;
    }
    api<{ email: string; message: string }>("/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    })
      .then((r) => {
        setEmail(r.email);
        setState("success");
      })
      .catch((e) => {
        setMessage(e.message || "Failed to verify email");
        setState("error");
      });
  }, [token]);

  useEffect(() => {
    if (state !== "error" || cooldown <= 0) return;
    const id = window.setInterval(() => setCooldown((v) => v - 1), 1000);
    return () => clearInterval(id);
  }, [state, cooldown]);

  return (
    <AuthFrame
      kind="verify"
      title={
        state === "loading"
          ? "Verifying your email…"
          : state === "success"
          ? "Your workspace is active."
          : "Verification link expired."
      }
      subtitle={
        state === "loading"
          ? "Confirming your secure cryptographic token."
          : state === "success"
          ? `${email} has been verified. Full API key generation and live ingestion are unlocked.`
          : message
      }
      footer={
        <Link className="font-ui-medium text-[#590907] font-semibold hover:underline" to="/login">
          Back to Sign In
        </Link>
      }
    >
      {state === "loading" && (
        <div className="py-8 text-center">
          <LoaderCircle className="mx-auto size-9 animate-spin text-[#590907]" />
        </div>
      )}
      {state === "success" && (
        <div>
          <span className="inline-flex items-center gap-1.5 rounded-full bg-[#d8efe0] border border-[#1b5e3a]/20 px-3 py-1 text-xs text-[#0b331e]">
            <CheckCircle2 className="size-4 text-[#1b5e3a]" />
            Email Verified
          </span>
          <div className="mt-4 rounded-lg border border-[#c6c8bb] bg-[#f6efe5] p-4">
            <p className="text-xs text-[#45483e]">Status</p>
            <code className="text-xs font-mono text-[#1b5e3a]">Confirmed · Active Workspace</code>
          </div>
          <Link to="/login">
            <Button className="mt-4 w-full">
              Go to Dashboard <ChevronRight className="size-4" />
            </Button>
          </Link>
        </div>
      )}
      {state === "error" && (
        <div className="space-y-4">
          <Input
            type="email"
            placeholder="secops@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Button
            className="w-full"
            variant="secondary"
            disabled={cooldown > 0 || !email}
            onClick={() =>
              api("/auth/resend-verification", {
                method: "POST",
                body: JSON.stringify({ email }),
              }).then(() => setCooldown(60))
            }
          >
            Resend verification {cooldown > 0 && `(${cooldown}s)`}
          </Button>
        </div>
      )}
    </AuthFrame>
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!cooldown) return;
    const id = setInterval(() => setCooldown((v) => v - 1), 1000);
    return () => clearInterval(id);
  }, [cooldown]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api("/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      setSent(true);
      setCooldown(60);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send reset email");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthFrame
      kind="forgot"
      title="Reset your password"
      subtitle="Enter your registered email address and we'll send you recovery instructions."
      footer={
        <div className="flex justify-between border-t border-[#c6c8bb] pt-4">
          <span>Remembered your password?</span>
          <Link className="font-ui-medium text-[#590907] font-semibold hover:underline" to="/login">
            Back to login
          </Link>
        </div>
      }
    >
      <form onSubmit={submit} onKeyDown={handleFieldProgression} className="space-y-4">
        {error && <ErrorMessage text={error} />}
        {sent && (
          <div className="rounded-lg border border-[#1b5e3a]/20 bg-[#d8efe0] p-3 text-sm leading-6 text-[#0b331e]">
            If an account with that email exists, password reset instructions have been sent.
          </div>
        )}
        <Input
          label="Email address"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="secops@company.com"
        />
        <Button className="w-full" loading={loading} disabled={cooldown > 0}>
          Send Reset Link {cooldown > 0 && `(${cooldown}s)`}
        </Button>
      </form>
    </AuthFrame>
  );
}

export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get("token");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!token) return setError("Invalid or missing reset token");
    if (password !== confirm) return setError("Passwords do not match");
    setLoading(true);
    try {
      await api("/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ token, new_password: password }),
      });
      setDone(true);
      setTimeout(() => navigate("/login"), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthFrame
      kind="reset"
      title="Set New Password"
      subtitle="Choose a strong password for your LogMorph account. Old sessions will be revoked automatically."
      footer={
        <Link className="font-ui-medium text-[#590907] font-semibold hover:underline" to="/login">
          Back to Sign In
        </Link>
      }
    >
      {done ? (
        <div className="rounded-lg border border-[#1b5e3a]/20 bg-[#d8efe0] p-4 text-sm text-[#0b331e]">
          <CheckCircle2 className="mb-2 size-6 text-[#1b5e3a]" />
          Password updated successfully. Redirecting to login in 3 seconds…
        </div>
      ) : (
        <form onSubmit={submit} onKeyDown={handleFieldProgression} className="space-y-4">
          {error && <ErrorMessage text={error} />}
          <div>
            <PasswordField
              label="New Password"
              value={password}
              onChange={setPassword}
              autoComplete="new-password"
            />
            <StrengthMeter password={password} />
          </div>
          <PasswordField
            label="Confirm New Password"
            value={confirm}
            onChange={setConfirm}
            autoComplete="new-password"
          />
          {confirm && (
            <p
              className={`text-xs ${
                password === confirm ? "text-[#1b5e3a]" : "text-[#93000a]"
              }`}
            >
              {password === confirm ? "Passwords match" : "Passwords do not match"}
            </p>
          )}
          <Button
            className="w-full"
            loading={loading}
            disabled={strength(password) < 1 || password !== confirm}
          >
            Reset Password
          </Button>
        </form>
      )}
    </AuthFrame>
  );
}

export function NotFoundPage() {
  return (
    <div className="grid min-h-screen place-items-center bg-[#faf6f0] p-6 text-center text-[#1a1d15]">
      <div className="max-w-md">
        <div className="font-mono text-7xl font-bold text-[#c6c8bb]">404</div>
        <h1 className="mt-2 text-2xl font-semibold text-[#1a1d15]">Route Not Found</h1>
        <p className="mt-2 text-sm text-[#45483e]">
          The telemetry route or resource you are looking for does not exist in the LogMorph routing table.
        </p>
        <Link to="/">
          <Button className="mt-6">Return to Overview</Button>
        </Link>
      </div>
    </div>
  );
}
