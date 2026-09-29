import './styles.css';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { AppProvider } from './state';
import { App } from './app';

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppProvider>
      <App />
    </AppProvider>
  </React.StrictMode>,
);
