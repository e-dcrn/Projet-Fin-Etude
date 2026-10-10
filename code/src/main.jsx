import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Styles de base de React Flow (à importer avant nos propres styles)
import '@xyflow/react/dist/style.css';
import './styles/app.css';

import App from './App.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
