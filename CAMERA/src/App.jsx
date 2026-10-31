import { useEffect, useState } from "react";
import { getHealth } from "./services/api";
import "./App.css";

function App() {
  const [apiStatus, setApiStatus] = useState("Checking...");
  const [apiMessage, setApiMessage] = useState("");

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const data = await getHealth();

        setApiStatus("Connected");
        setApiMessage(data.message);
      } catch (error) {
        setApiStatus("Disconnected");
        setApiMessage(
          error.response?.data?.message || error.message
        );
      }
    };

    checkBackend();
  }, []);

  return (
    <main>
      <h1>Cloud Attack-Surface Decay Tracker</h1>

      <section>
        <h2>Backend Connection</h2>
        <p>API Status: <strong>{apiStatus}</strong></p>
        <p>{apiMessage}</p>
      </section>
    </main>
  );
}

export default App;