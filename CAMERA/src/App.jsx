import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getHealth,
  getScanHistory,
  scanAwsInventory,
  scanDomain,
} from "./services/api";
import "./App.css";

function getRecordCount(host) {
  const records = host?.records || {};
  return Object.values(records).reduce(
    (count, values) => count + (Array.isArray(values) ? values.length : values ? 1 : 0),
    0
  );
}

function SeverityPill({ severity = "info" }) {
  const allowed = ["critical", "high", "medium", "low", "info"];
  const normalized = String(severity).toLowerCase();
  const value = allowed.includes(normalized) ? normalized : "info";
  return <span className={`severity-pill ${value}`}>{value}</span>;
}

function App() {
  const [backendStatus, setBackendStatus] = useState("Checking");
  const [domain, setDomain] = useState("python.org");
  const [region, setRegion] = useState("ap-south-1");
  const [scanData, setScanData] = useState(null);
  const [awsData, setAwsData] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [awsLoading, setAwsLoading] = useState(false);
  const [error, setError] = useState("");
  const [awsError, setAwsError] = useState("");

  const refreshHistory = useCallback(async () => {
    try {
      const response = await getScanHistory(8);
      setHistory(response.data || []);
    } catch {
      setHistory([]);
    }
  }, []);

  useEffect(() => {
    getHealth()
      .then(() => setBackendStatus("Connected"))
      .catch(() => setBackendStatus("Disconnected"));
    refreshHistory();
  }, [refreshHistory]);

  const hosts = scanData?.data?.dns?.results || [];
  const findings = scanData?.data?.findings || [];
  const discovery = scanData?.data?.discovery;
  const cnameAssessments = scanData?.data?.cname_assessments || [];
  const awsInventory = awsData?.data?.inventory;
  const awsFindings = awsData?.data?.findings || [];
  const correlations = awsData?.data?.correlations || [];

  const resolvedCount = hosts.filter((host) => host.status === "resolved").length;
  const partialCount = hosts.filter((host) => host.status === "partial").length;
  const nxdomainCount = hosts.filter((host) => host.status === "nxdomain").length;
  const recordCount = hosts.reduce((total, host) => total + getRecordCount(host), 0);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((finding) => {
      const severity = String(finding.severity || "info").toLowerCase();
      if (Object.hasOwn(counts, severity)) counts[severity] += 1;
    });
    return counts;
  }, [findings]);

  const handleDomainScan = async (event) => {
    event.preventDefault();
    const requestedDomain = domain.trim();
    if (!requestedDomain) {
      setError("Enter a root domain.");
      return;
    }

    setLoading(true);
    setError("");
    setAwsError("");
    setScanData(null);
    setAwsData(null);

    try {
      const response = await scanDomain(requestedDomain);
      setScanData(response);
      await refreshHistory();
    } catch (err) {
      setError(
        err.response?.data?.message ||
        err.message ||
        "Domain assessment failed."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleAwsScan = async () => {
    setAwsLoading(true);
    setAwsError("");
    setAwsData(null);

    try {
      const response = await scanAwsInventory({
        region,
        dnsResults: hosts,
      });
      setAwsData(response);
    } catch (err) {
      setAwsError(
        err.response?.data?.message ||
        err.message ||
        "AWS inventory scan failed."
      );
    } finally {
      setAwsLoading(false);
    }
  };

  const exportReport = () => {
    if (!scanData) return;
    const report = {
      generated_at: new Date().toISOString(),
      domain_scan: scanData,
      aws_scan: awsData,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `cast-report-${scanData.data?.domain || "scan"}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="CAST home">
          <span className="brand-mark">C</span>
          <span>
            <strong>CAST</strong>
            <small>Cloud Attack-Surface Decay Tracker</small>
          </span>
        </a>
        <div className="topbar-right">
          <span className="eyebrow">CLOUD SECURITY INTELLIGENCE</span>
          <span className={`connection-chip ${backendStatus === "Connected" ? "online" : "offline"}`}>
            <i />
            API {backendStatus}
          </span>
        </div>
      </header>

      <section className="hero" id="top">
        <div>
          <p className="section-kicker">EXTERNAL ATTACK SURFACE · LIFECYCLE VISIBILITY</p>
          <h1>Find what was <span>left behind.</span></h1>
          <p className="hero-copy">
            Discover public hostnames, inspect DNS dependencies and correlate
            observations with authorized cloud inventory.
          </p>
        </div>
        <div className="hero-stamp">
          <span className="stamp-dot" />
          <span>READ-ONLY DISCOVERY</span>
        </div>
      </section>

      <section className="panel scan-panel">
        <div className="panel-heading">
          <div>
            <p className="section-kicker">01 / DISCOVERY</p>
            <h2>Domain intelligence scan</h2>
            <p>Certificate Transparency discovery followed by DNS inspection.</p>
          </div>
          <span className="step-number">01</span>
        </div>

        <form className="scan-form" onSubmit={handleDomainScan}>
          <label htmlFor="domain">Root domain</label>
          <div className="scan-controls">
            <input
              id="domain"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="example.com"
              autoComplete="url"
            />
            <button className="primary-button" type="submit" disabled={loading}>
              {loading ? "Scanning…" : "Start domain scan"}
            </button>
          </div>
        </form>
        {loading && (
          <div className="progress-line">
            <span />
            <p>Querying Certificate Transparency and resolving selected DNS records…</p>
          </div>
        )}
        {error && <div className="alert error-alert">{error}</div>}
        {scanData && (
          <div className="alert success-alert">
            {scanData.message}
            {scanData.history_saved === false && " Scan history could not be saved."}
          </div>
        )}
      </section>

      {scanData && (
        <>
          <section className="metric-grid">
            <Metric label="CT hostnames" value={discovery?.total_discovered ?? 0} detail="Discovered candidates" />
            <Metric label="Hosts assessed" value={hosts.length} detail="Root + selected hosts" />
            <Metric label="Resolved" value={resolvedCount} detail={`${partialCount} partial · ${nxdomainCount} NXDOMAIN`} />
            <Metric label="DNS records" value={recordCount} detail="A · AAAA · CNAME · NS · MX" />
            <Metric label="Findings" value={findings.length} detail="Evidence-based observations" />
          </section>

          <section className="panel">
            <div className="panel-heading compact">
              <div>
                <p className="section-kicker">02 / OBSERVATIONS</p>
                <h2>Security findings</h2>
                <p>Signals to investigate—not confirmed vulnerabilities.</p>
              </div>
              <div className="panel-actions">
                <button className="secondary-button" onClick={exportReport} type="button">Export JSON</button>
              </div>
            </div>

            <div className="severity-strip">
              {Object.entries(severityCounts).map(([severity, count]) => (
                <div className="severity-counter" key={severity}>
                  <SeverityPill severity={severity} />
                  <strong>{count}</strong>
                </div>
              ))}
            </div>

            {findings.length === 0 ? (
              <div className="empty-state">No findings were generated in this assessment.</div>
            ) : (
              <div className="finding-grid">
                {findings.map((finding, index) => (
                  <article className="finding-card" key={finding.id || index}>
                    <div className="finding-card-top">
                      <span className="finding-type">{finding.type?.replaceAll("_", " ") || "Observation"}</span>
                      <SeverityPill severity={finding.severity} />
                    </div>
                    <h3>{finding.title}</h3>
                    <p className="finding-host">{finding.hostname}</p>
                    {finding.target && <p className="finding-target">Target: {finding.target}</p>}
                    <p className="finding-description">{finding.description}</p>
                    <div className="finding-confidence">
                      Confidence <strong>{finding.confidence || "unknown"}</strong>
                    </div>
                    {finding.evidence?.length > 0 && (
                      <div className="evidence-block">
                        <strong>Evidence</strong>
                        <ul>{finding.evidence.map((item, i) => <li key={i}>{item}</li>)}</ul>
                      </div>
                    )}
                    {finding.recommendation && (
                      <div className="recommendation-block">
                        <strong>Recommended action</strong>
                        <p>{finding.recommendation}</p>
                      </div>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="panel">
            <div className="panel-heading compact">
              <div>
                <p className="section-kicker">03 / DNS DEPENDENCIES</p>
                <h2>External CNAME verification</h2>
                <p>Checks whether external CNAME destinations currently resolve.</p>
              </div>
              <span className="count-chip">{cnameAssessments.length} targets</span>
            </div>
            {scanData.data?.cname_assessment_error && (
              <div className="alert warning-alert">{scanData.data.cname_assessment_error}</div>
            )}
            {cnameAssessments.length === 0 ? (
              <div className="empty-state">No external CNAME targets were available for verification.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Source hostname</th><th>CNAME target</th><th>Verification</th><th>Evidence</th></tr></thead>
                  <tbody>
                    {cnameAssessments.map((item, index) => (
                      <tr key={`${item.hostname}-${item.target}-${index}`}>
                        <td>{item.hostname}</td>
                        <td className="mono">{item.target}</td>
                        <td><StatusPill status={item.status} /></td>
                        <td>{item.evidence || (item.errors || []).join("; ") || "No additional evidence"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="subtle-note">
              NXDOMAIN is a potential dangling-reference indicator only. It does not demonstrate that the third-party resource is claimable.
            </p>
          </section>

          <section className="panel">
            <div className="panel-heading compact">
              <div>
                <p className="section-kicker">04 / HOST INVENTORY</p>
                <h2>Discovered hostnames</h2>
              </div>
              <span className="count-chip">{hosts.length} assessed</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Hostname</th><th>DNS status</th><th>Records</th><th>Errors</th></tr></thead>
                <tbody>
                  {hosts.map((host) => (
                    <tr key={host.hostname}>
                      <td className="mono">{host.hostname}</td>
                      <td><StatusPill status={host.status} /></td>
                      <td>{getRecordCount(host)}</td>
                      <td>{(host.errors || []).map((item) => item.reason || item).join("; ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading compact">
              <div>
                <p className="section-kicker">05 / DNS RECORDS</p>
                <h2>DNS observations</h2>
              </div>
              <span className="count-chip">{recordCount} records</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Hostname</th><th>Type</th><th>Value</th><th>TTL</th></tr></thead>
                <tbody>
                  {hosts.flatMap((host) =>
                    Object.entries(host.records || {}).flatMap(([type, values]) => {
                      const list = Array.isArray(values) ? values : values == null ? [] : [values];
                      return (list.length ? list : ["No record"]).map((value, index) => (
                        <tr key={`${host.hostname}-${type}-${index}`}>
                          <td className="mono">{host.hostname}</td>
                          <td><span className="record-type">{type}</span></td>
                          <td className="mono">{String(value)}</td>
                          <td>{host.ttl_seconds?.[type] != null ? `${host.ttl_seconds[type]}s` : "—"}</td>
                        </tr>
                      ));
                    })
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      <section className="panel aws-panel">
        <div className="panel-heading compact">
          <div>
            <p className="section-kicker">06 / CLOUD CORRELATION</p>
            <h2>AWS inventory</h2>
            <p>Read-only EC2, EBS and S3 metadata collection plus exact IP correlation.</p>
          </div>
          <span className="step-number">AWS</span>
        </div>
        <div className="aws-controls">
          <label htmlFor="region">AWS region</label>
          <select id="region" value={region} onChange={(event) => setRegion(event.target.value)}>
            <option value="ap-south-1">Asia Pacific (Mumbai) · ap-south-1</option>
            <option value="us-east-1">US East (N. Virginia) · us-east-1</option>
            <option value="us-east-2">US East (Ohio) · us-east-2</option>
            <option value="us-west-2">US West (Oregon) · us-west-2</option>
            <option value="eu-west-1">Europe (Ireland) · eu-west-1</option>
          </select>
          <button className="secondary-button" type="button" onClick={handleAwsScan} disabled={awsLoading}>
            {awsLoading ? "Collecting inventory…" : "Scan connected AWS account"}
          </button>
        </div>
        <p className="subtle-note">
          Requires a configured read-only AWS identity on the backend machine. No AWS credentials are sent to the browser.
        </p>
        {awsError && <div className="alert warning-alert">{awsError}</div>}
        {awsData && awsInventory && (
          <>
            <div className="metric-grid aws-metrics">
              <Metric label="AWS resources" value={awsInventory.total_resources} detail={`Account ${awsInventory.account_id}`} />
              <Metric label="AWS findings" value={awsFindings.length} detail="Ownership and configuration indicators" />
              <Metric label="IP correlations" value={correlations.filter((item) => item.status === "matched").length} detail={`${correlations.length} DNS IPs checked`} />
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Resource type</th><th>Resource ID</th><th>State</th><th>Ownership tags</th></tr></thead>
                <tbody>
                  {awsInventory.resources.map((resource) => (
                    <tr key={`${resource.resource_type}-${resource.resource_id}`}>
                      <td>{resource.resource_type}</td>
                      <td className="mono">{resource.resource_id}</td>
                      <td>{resource.state || "—"}</td>
                      <td>{Object.keys(resource.tags || {}).join(", ") || "None"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {awsFindings.length > 0 && (
              <div className="aws-findings">
                <h3>AWS inventory findings</h3>
                {awsFindings.map((finding) => (
                  <div className="compact-finding" key={finding.id}>
                    <SeverityPill severity={finding.severity} />
                    <strong>{finding.title}</strong>
                    <span>{finding.hostname}</span>
                  </div>
                ))}
              </div>
            )}
            <div className="aws-findings">
              <h3>DNS to EC2 IP correlations</h3>
              {correlations.length === 0 ? (
                <p className="subtle-note">No DNS A/AAAA addresses were supplied for correlation.</p>
              ) : correlations.map((item, index) => (
                <div className="compact-finding" key={`${item.hostname}-${item.ip_address}-${index}`}>
                  <StatusPill status={item.status} />
                  <strong>{item.hostname}</strong>
                  <span className="mono">{item.ip_address}</span>
                  <span>{item.resources.map((resource) => resource.resource_id).join(", ") || "No exact match"}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </section>

      <section className="panel history-panel">
        <div className="panel-heading compact">
          <div>
            <p className="section-kicker">07 / AUDIT TRAIL</p>
            <h2>Recent scan history</h2>
          </div>
          <button className="text-button" type="button" onClick={refreshHistory}>Refresh</button>
        </div>
        {history.length === 0 ? (
          <div className="empty-state">No saved scans yet. Complete a domain scan to create the first history entry.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Domain</th><th>Scanned at</th><th>Hosts</th><th>Findings</th><th>Status</th></tr></thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id}>
                    <td className="mono">{item.domain}</td>
                    <td>{new Date(item.created_at).toLocaleString()}</td>
                    <td>{item.hosts_assessed}</td>
                    <td>{item.findings_count}</td>
                    <td><StatusPill status={item.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <footer className="footer">
        <span>CAST · Cloud Attack-Surface Decay Tracker</span>
        <span>Passive discovery and read-only inventory · Verify findings before remediation</span>
      </footer>
    </main>
  );
}

function Metric({ label, value, detail }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value ?? "—"}</strong>
      <small>{detail}</small>
    </article>
  );
}

function StatusPill({ status = "unknown" }) {
  const safe = String(status).toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return <span className={`status-pill ${safe}`}>{String(status).replaceAll("_", " ")}</span>;
}

export default App;
