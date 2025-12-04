// File: frontend/src/components/Login/Login.js

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, AlertCircle, CheckCircle } from 'lucide-react';
import { authAPI } from '../../services/api';
import './Login.css';

function Login({ onLogin }) {
  const navigate = useNavigate();
  const [roleArn, setRoleArn] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    // Validate ARN format
    if (!roleArn.trim().startsWith('arn:aws:iam::')) {
      setError('Invalid IAM Role ARN format. Must start with "arn:aws:iam::"');
      setLoading(false);
      return;
    }

    try {
      const response = await authAPI.login(roleArn.trim());
      setSuccess('Authentication successful! Redirecting...');
      
      setTimeout(() => {
        onLogin(response.data.session_token);
        navigate('/dashboard');
      }, 1000);
    } catch (err) {
      setError(
        err.response?.data?.detail || 
        'Authentication failed. Please check your IAM Role ARN and permissions.'
      );
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <Shield className="login-icon" size={48} />
          <h1>SecOps</h1>
          <p>AWS Security Operations Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="roleArn">
              <Lock size={18} />
              IAM Role ARN
            </label>
            <input
              id="roleArn"
              type="text"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/YourRoleName"
              required
              disabled={loading}
              className="form-input"
            />
            <small className="form-hint">
              Enter the IAM Role ARN that you want to assume for resource scanning
            </small>
          </div>

          {error && (
            <div className="alert alert-error">
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="alert alert-success">
              <CheckCircle size={18} />
              <span>{success}</span>
            </div>
          )}

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={loading || !roleArn.trim()}
          >
            {loading ? (
              <>
                <div className="spinner"></div>
                Authenticating...
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <div className="login-footer">
          <div className="security-notice">
            <Shield size={16} />
            <span>Your credentials are stored in-memory only and never persisted</span>
          </div>
        </div>
      </div>

      <div className="setup-instructions">
        <h3>Setup Instructions</h3>
        <ol>
          <li>Ensure your EC2 instance has an IAM role with <code>sts:AssumeRole</code> permission</li>
          <li>The IAM role you're assuming must trust your EC2 instance</li>
          <li>The role should have appropriate read permissions for AWS services</li>
        </ol>
      </div>
    </div>
  );
}

export default Login;
