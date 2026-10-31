
import { useEffect, useState } from "react";
import { getHealth, scanDns } from "./services/api";
import "./App.css";

function App() {
  const [apiStatus, setApiStatus] = useState("Checking...");
  const [hostnames, setHostnames] = useState(
    "example.com\nwww.example.com"
  );

  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanMessage, setScanMessage] = useState("");

  useEffect(() => {
    const checkBackend = async () => {
      try {
        await getHealth();
        setApiStatus("Connected");
      } catch {
        setApiStatus("Disconnected");
      }
    };

    checkBackend();
  }, []);

  const handleScan = async (event) => {
    event.preventDefault();

    const domains = [
      ...new Set(
        hostnames
          .split(/[\n,]+/)
          .map((hostname) => hostname.trim())
          .filter(Boolean)
      ),
    ];

    if (domains.length === 0) {
      setError("Enter at least one hostname.");
      return;
    }

    if (domains.length > 25) {
      setError("Maximum 25 hostnames per scan.");
      return;
    }

    setLoading(true);
    setError("");
    setScanMessage("");
    setResults([]);

    try {
      const response = await scanDns(domains);

      setResults(response.data.results);
      setScanMessage(response.message);
    } catch (err) {
      setError(
        err.response?.data?.message ||
        "Could not complete DNS scan."
      );
    } finally {
      setLoading(false);
    }
  };

  const totalResolved = results.filter(
    (item) => item.status === "resolved"
  ).length;

  const totalRecords = results.reduce(
    (total, item) =>
      total +
      Object.values(item.records).reduce(
        (count, values) => count + values.length,
        0
      ),
    0
  );

  return (
    <main className="app-container">
      <header className="app-header">
        <div>
          <p className="eyebrow">CLOUD SECURITY INTELLIGENCE</p>
          <h1>CAST</h1>
          <p>
            Cloud Attack-Surface Decay Tracker
          </p>
        </div>

        <div className="connection-status">
          <span
            className={
              apiStatus === "Connected"
                ? "status-dot online"
                : "status-dot offline"
            }
          />
          Backend: {apiStatus}
        </div>
      </header>

      <section className="scan-panel">
        <h2>DNS Intelligence Scanner</h2>

        <p>
          Resolve DNS records for authorized hostnames.
        </p>

        <form onSubmit={handleScan}>
          <label htmlFor="hostnames">
            Target hostnames
          </label>

          <textarea
            id="hostnames"
            value={hostnames}
            onChange={(event) =>
              setHostnames(event.target.value)
            }
            placeholder="example.com&#10;www.example.com"
            rows={5}
          />

          <button type="submit" disabled={loading}>
            {loading ? "Scanning..." : "Start DNS Scan"}
          </button>
        </form>

        {error && (
          <p className="error-message">{error}</p>
        )}

        {scanMessage && (
          <p className="success-message">
            {scanMessage}
          </p>
        )}
      </section>

      <section className="summary-grid">
        <div className="summary-card">
          <span>Hostnames scanned</span>
          <strong>{results.length}</strong>
        </div>

        <div className="summary-card">
          <span>Resolved hostnames</span>
          <strong>{totalResolved}</strong>
        </div>

        <div className="summary-card">
          <span>DNS records found</span>
          <strong>{totalRecords}</strong>
        </div>
      </section>

      <section className="results-panel">
        <h2>DNS Scan Results</h2>

        {results.length === 0 ? (
          <p className="empty-state">
            No scan results yet. Start a DNS scan.
          </p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Status</th>
                  <th>Record type</th>
                  <th>Record value</th>
                  <th>TTL</th>
                </tr>
              </thead>

              <tbody>
                {results.flatMap((host, hostIndex) =>
                  Object.entries(host.records).map(
                    ([type, values]) => (
                      <tr key={`${hostIndex}-${type}`}>
                        <td>{host.hostname}</td>
                        <td>{host.status}</td>
                        <td>{type}</td>
                        <td>
                          {values.length > 0
                            ? values.join(", ")
                            : "No record"}
                        </td>
                        <td>
                          {host.ttl_seconds[type]
                            ? `${host.ttl_seconds[type]}s`
                            : "—"}
                        </td>
                      </tr>
                    )
                  )
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;
