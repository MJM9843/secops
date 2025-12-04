// File: frontend/src/App.js

import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login/Login';
import Dashboard from './components/Dashboard/Dashboard';
import CISBenchmark from './components/CISBenchmark/CISBenchmark';
import './App.css';

function App() {
  const [sessionToken, setSessionToken] = useState(
    localStorage.getItem('sessionToken') || null
  );

  useEffect(() => {
    if (sessionToken) {
      localStorage.setItem('sessionToken', sessionToken);
    } else {
      localStorage.removeItem('sessionToken');
    }
  }, [sessionToken]);

  const handleLogin = (token) => {
    setSessionToken(token);
  };

  const handleLogout = () => {
    setSessionToken(null);
    localStorage.removeItem('sessionToken');
  };

  return (
    <Router>
      <div className="App">
        <Routes>
          <Route 
            path="/login" 
            element={
              sessionToken ? 
              <Navigate to="/dashboard" /> : 
              <Login onLogin={handleLogin} />
            } 
          />
          <Route 
            path="/dashboard" 
            element={
              sessionToken ? 
              <Dashboard sessionToken={sessionToken} onLogout={handleLogout} /> : 
              <Navigate to="/login" />
            } 
          />
          <Route 
            path="/cis-benchmark" 
            element={
              sessionToken ? 
              <CISBenchmark sessionToken={sessionToken} onLogout={handleLogout} /> : 
              <Navigate to="/login" />
            } 
          />
          <Route path="/" element={<Navigate to="/login" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
