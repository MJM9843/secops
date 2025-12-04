// File: frontend/src/services/api.js

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000, // 2 minutes for long-running scans
  headers: {
    'Content-Type': 'application/json',
  },
});

// Authentication APIs
export const authAPI = {
  login: (roleArn) => 
    api.post('/auth/login', { role_arn: roleArn }),
  
  logout: (sessionToken) => 
    api.post('/auth/logout', { session_token: sessionToken }),
  
  validateSession: (sessionToken) => 
    api.get('/auth/validate', { params: { session_token: sessionToken } }),
};

// Resources APIs
export const resourcesAPI = {
  scan: (sessionToken, region = null, service = null) => 
    api.get('/resources/scan', { 
      params: { 
        session_token: sessionToken,
        region,
        service
      } 
    }),
  
  getServices: () => 
    api.get('/resources/services'),
  
  getRegions: () => 
    api.get('/resources/regions'),
};

// CIS Benchmark APIs
export const cisAPI = {
  scan: (sessionToken, region = null, service = null) => 
    api.get('/cis/scan', { 
      params: { 
        session_token: sessionToken,
        region,
        service
      } 
    }),
  
  remediate: (sessionToken, region, checkId, resourceIds) => 
    api.post('/cis/remediate', {
      session_token: sessionToken,
      region,
      check_id: checkId,
      resource_ids: resourceIds
    }),
  
  getRemediationHistory: (sessionToken, region = null) => 
    api.get('/cis/remediation-history', {
      params: {
        session_token: sessionToken,
        region
      }
    }),
  
  rollback: (sessionToken, region, remediationId) => 
    api.post('/cis/rollback', null, {
      params: {
        session_token: sessionToken,
        region,
        remediation_id: remediationId
      }
    }),
};

export default api;
