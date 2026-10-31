
import { useEffect, useState } from "react";
import { getHealth, scanDomain } from "./services/api";
import "./App.css";

function getRecordCount(host) {
  const records = host?.records || {};

  return Object.values(records).reduce(
    (count, values) =>
      count + (Array.isArray(values) ? values.length : values ? 1 : 0),
    0
  );
}

function getSeverityClass(severity) {
  const allowed = ["critical", "high", "medium", "low", "info"];
  const normalized = String(severity || "info").toLowerCase();

  return allowed.includes(normalized) ? normalized : "info";
}

function App() {
  const [backendStatus, setBackendStatus] = useState("Checking...");
  const [domain, setDomain] = useState("python.org");
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    getHealth()
      .then(() => setBackendStatus("Connected"))
      .catch(() => setBackendStatus("Disconnected"));
  }, []);

  const handleScan = async (event) => {
    event.preventDefault();

    if (!domain.trim()) {
      setError("Enter a root domain.");
      return;
    }

    setLoading(true);
    setError("");
    setScanData(null);

    try {
      const response = await scanDomain(domain.trim());
      setScanData(response);
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

  const discovery = scanData?.data?.discovery;
  const hosts = scanData?.data?.dns?.results || [];
  const findings = scanData?.data?.findings || [];

  const resolvedCount = hosts.filter(
    (host) => host.status === "resolved"
  ).length;

  const partialCount = hosts.filter(
    (host) => host.status === "partial"
  ).length;

  const nxdomainCount = hosts.filter(
    (host) => host.status === "nxdomain"
  ).length;

  const recordCount = hosts.reduce(
    (total, host) => total + getRecordCount(host),
    0
  );

  const severityCounts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  return (
    <main className="app-container">

      {/* HEADER */}
      <header className="app-header">
        <div>
          <p className="eyebrow">CLOUD SECURITY INTELLIGENCE</p>
          <h1>CAST</h1>
          <p>Cloud Attack-Surface Decay Tracker</p>
        </div>

        <div className="connection-status">
          <span
            className={
              backendStatus === "Connected"
                ? "status-dot online"
                : "status-dot offline"
            }
          />
          Backend: {backendStatus}
        </div>
      </header>

      {/* DOMAIN SCANNER */}
      <section className="scan-panel">
        <h2>Domain Intelligence Scanner</h2>

        <p>
          Discover subdomains and resolve their DNS records.
        </p>

        <form onSubmit={handleScan}>
          <label htmlFor="domain">Root domain</label>

          <input
            id="domain"
            className="domain-input"
            type="text"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder="example.com"
          />

          <button type="submit" disabled={loading}>
            {loading ? "Discovering and scanning..." : "Start Domain Scan"}
          </button>
        </form>

        {loading && (
          <p>Discovering hostnames and resolving DNS...</p>
        )}

        {error && (
          <p className="error-message">{error}</p>
        )}

        {scanData && (
          <p className="success-message">
            {scanData.message}
          </p>
        )}
      </section>

      {/* SCAN RESULTS */}
      {scanData && (
        <>

          {/* SUMMARY */}
          <section className="summary-grid domain-summary">

            <div className="summary-card">
              <span>Subdomains discovered</span>
              <strong>{discovery?.total_discovered ?? 0}</strong>
            </div>

            <div className="summary-card">
              <span>Hosts assessed</span>
              <strong>{hosts.length}</strong>
            </div>

            <div className="summary-card">
              <span>Resolved hosts</span>
              <strong>{resolvedCount}</strong>
            </div>

            <div className="summary-card">
              <span>DNS records</span>
              <strong>{recordCount}</strong>
            </div>

            <div className="summary-card">
              <span>Security findings</span>
              <strong>{findings.length}</strong>
            </div>

          </section>

          {/* DISCOVERY STATUS */}
          <section className="scan-panel">
            <h2>Discovery Status</h2>

            <p>
              Certificate Transparency:{" "}
              <strong>{discovery?.status || "Unknown"}</strong>
            </p>

            <p>DNS partial results: {partialCount}</p>
            <p>NXDOMAIN results: {nxdomainCount}</p>

            {discovery?.error && (
              <p className="error-message">
                CT discovery notice: {discovery.error}
              </p>
            )}
          </section>

          {/* SECURITY FINDINGS */}
          <section className="results-panel findings-panel">

            <div className="findings-heading">
              <div>
                <h2>Security Findings</h2>
                <p>
                  Observations requiring security investigation.
                </p>
              </div>

              <strong className="finding-total">
                {findings.length} findings
              </strong>
            </div>

            <div className="finding-severity-summary">
              {Object.entries(severityCounts).map(([severity, count]) => (
                <div className="severity-summary-item" key={severity}>
                  <span className={`severity-pill ${severity}`}>
                    {severity}
                  </span>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>

            {findings.length === 0 ? (
              <div className="empty-findings">
                No findings were generated for this assessment.
              </div>
            ) : (

              <div className="finding-list">

                {findings.map((finding, index) => (
                  <article
                    className="finding-card"
                    key={finding.id || index}
                  >

                    <div className="finding-card-header">
                      <h3>{finding.title}</h3>

                      <span
                        className={`severity-pill ${getSeverityClass(
                          finding.severity
                        )}`}
                      >
                        {finding.severity || "info"}
                      </span>
                    </div>

                    <p className="finding-hostname">
                      {finding.hostname}
                    </p>

                    <p className="finding-description">
                      {finding.description}
                    </p>

                    <div className="finding-meta">
                      <span>
                        Confidence:{" "}
                        <strong>{finding.confidence || "Unknown"}</strong>
                      </span>

                      <span>
                        Type:{" "}
                        <strong>{finding.type || "Observation"}</strong>
                      </span>
                    </div>

                    {finding.evidence?.length > 0 && (
                      <div className="finding-evidence">
                        <strong>Evidence</strong>
                        <ul>
                          {finding.evidence.map((item, i) => (
                            <li key={i}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {finding.recommendation && (
                      <div className="finding-recommendation">
                        <strong>Recommended action</strong>
                        <p>{finding.recommendation}</p>
                      </div>
                    )}

                  </article>
                ))}

              </div>
            )}

            <p className="findings-disclaimer">
              Findings are investigation leads based on observed DNS data.
              They are not confirmed vulnerabilities.
            </p>

          </section>

          {/* DISCOVERED HOSTNAMES */}
          <section className="results-panel">
            <h2>Discovered Hostnames</h2>

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Status</th>
                    <th>Records found</th>
                    <th>Errors</th>
                  </tr>
                </thead>

                <tbody>
                  {hosts.map((host) => {
                    const errors = Array.isArray(host.errors)
                      ? host.errors
                      : [];

                    return (
                      <tr key={host.hostname}>
                        <td>{host.hostname}</td>
                        <td>{host.status}</td>
                        <td>{getRecordCount(host)}</td>
                        <td>
                          {errors.length
                            ? errors.map((item, index) =>
                              typeof item === "string"
                                ? item
                                : `${item.record_type}: ${item.reason}`
                            ).join("; ")
                            : "None"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {/* DNS RECORDS */}
          <section className="results-panel">
            <h2>DNS Records</h2>

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Type</th>
                    <th>Record value</th>
                    <th>TTL</th>
                  </tr>
                </thead>

                <tbody>
                  {hosts.flatMap((host) =>
                    Object.entries(host.records || {}).flatMap(
                      ([type, values]) => {

                        const recordValues = Array.isArray(values)
                          ? values
                          : values == null
                            ? []
                            : [values];

                        const displayedValues = recordValues.length
                          ? recordValues
                          : ["No record"];

                        return displayedValues.map((record, index) => {
                          const value =
                            typeof record === "object" && record !== null
                              ? record.value ?? record.data ?? JSON.stringify(record)
                              : record;

                          const ttl =
                            typeof record === "object" && record !== null
                              ? record.ttl ?? host.ttl_seconds?.[type]
                              : host.ttl_seconds?.[type];

                          return (
                            <tr
                              key={`${host.hostname}-${type}-${index}`}
                            >
                              <td>{host.hostname}</td>
                              <td>{type}</td>
                              <td>{String(value)}</td>
                              <td>
                                {ttl !== undefined && ttl !== null
                                  ? `${ttl}s`
                                  : "—"}
                              </td>
                            </tr>
                          );
                        });
                      }
                    )
                  )}
                </tbody>
              </table>
            </div>
          </section>

        </>
      )}

    </main>
  );
}

export default App;
