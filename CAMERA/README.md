# CAST Frontend

React 19 + Vite dashboard for the Cloud Attack-Surface Decay Tracker.

## Run

From this directory:

\`\`\`powershell
npm install
npm run dev
\`\`\`

The backend should be running at http://127.0.0.1:5000. Override the API URL by creating \`.env.local\`:

\`\`\`env
VITE_API_BASE_URL=http://127.0.0.1:5000
\`\`\`

Do not place AWS credentials or other secrets in Vite environment variables.

## Build and lint

\`\`\`powershell
npm run lint
npm run build
\`\`\`
