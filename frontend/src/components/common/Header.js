// File: frontend/src/components/common/Header.js

import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, LogOut, LayoutDashboard, FileCheck } from 'lucide-react';
import './Header.css';

function Header({ title, onLogout }) {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <header className="app-header">
      <div className="header-container">
        <div className="header-left">
          <Shield className="header-logo" size={32} />
          <div className="header-brand">
            <h1>SecOps</h1>
            <span className="header-subtitle">{title}</span>
          </div>
        </div>

        <nav className="header-nav">
          <button 
            className={`nav-btn ${location.pathname === '/dashboard' ? 'active' : ''}`}
            onClick={() => navigate('/dashboard')}
          >
            <LayoutDashboard size={18} />
            Dashboard
          </button>
          
          <button 
            className={`nav-btn ${location.pathname === '/cis-benchmark' ? 'active' : ''}`}
            onClick={() => navigate('/cis-benchmark')}
          >
            <FileCheck size={18} />
            CIS Benchmark
          </button>
        </nav>

        <button className="logout-btn" onClick={onLogout}>
          <LogOut size={18} />
          Logout
        </button>
      </div>
    </header>
  );
}

export default Header;
