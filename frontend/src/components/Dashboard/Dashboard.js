// File: frontend/src/components/Dashboard/Dashboard.js

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, LogOut, RefreshCw, Filter, Server, 
  Database, HardDrive, Lock, Cloud, Activity 
} from 'lucide-react';
import { resourcesAPI, authAPI } from '../../services/api';
import Header from '../common/Header';
import './Dashboard.css';

function Dashboard({ sessionToken, onLogout }) {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [resources, setResources] = useState({});
  const [summary, setSummary] = useState(null);
  const [selectedRegion, setSelectedRegion] = useState('all');
  const [selectedService, setSelectedService] = useState('all');
  const [regions, setRegions] = useState([]);
  const [services, setServices] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    loadMetadata();
  }, []);

  const loadMetadata = async () => {
    try {
      const [regionsRes, servicesRes] = await Promise.all([
        resourcesAPI.getRegions(),
        resourcesAPI.getServices()
      ]);
      
      setRegions(regionsRes.data.regions);
      setServices(servicesRes.data.services);
    } catch (err) {
      console.error('Failed to load metadata:', err);
    }
  };

  const handleScan = async () => {
    setLoading(true);
    setError('');
    
    try {
      const region = selectedRegion === 'all' ? null : selectedRegion;
      const service = selectedService === 'all' ? null : selectedService;
      
      const response = await resourcesAPI.scan(sessionToken, region, service);
      setResources(response.data.resources);
      setSummary(response.data.summary);
    } catch (err) {
      if (err.response?.status === 401) {
        setError('Session expired. Please login again.');
        setTimeout(() => {
          onLogout();
          navigate('/login');
        }, 2000);
      } else {
        setError(err.response?.data?.detail || 'Failed to scan resources');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await authAPI.logout(sessionToken);
    } catch (err) {
      console.error('Logout error:', err);
    }
    onLogout();
    navigate('/login');
  };

  const getServiceIcon = (serviceId) => {
    const icons = {
      'ec2': Server,
      's3': Database,
      'rds': Database,
      'lambda': Activity,
      'volumes': HardDrive,
      'snapshots': HardDrive,
      'security-groups': Lock,
      'vpc': Cloud,
    };
    return icons[serviceId] || Server;
  };

  return (
    <div className="dashboard">
      <Header 
        title="Resource Dashboard"
        onLogout={handleLogout}
        sessionToken={sessionToken}
      />

      <div className="dashboard-content">
        {/* Filters Section */}
        <div className="filters-card">
          <div className="filters-header">
            <Filter size={20} />
            <h3>Filters</h3>
          </div>
          
          <div className="filters-grid">
            <div className="filter-group">
              <label>Region</label>
              <select 
                value={selectedRegion} 
                onChange={(e) => setSelectedRegion(e.target.value)}
                disabled={loading}
              >
                <option value="all">All Regions</option>
                {regions.map(region => (
                  <option key={region.id} value={region.id}>
                    {region.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label>Service</label>
              <select 
                value={selectedService} 
                onChange={(e) => setSelectedService(e.target.value)}
                disabled={loading}
              >
                <option value="all">All Services</option>
                {services.map(service => (
                  <option key={service.id} value={service.id}>
                    {service.name}
                  </option>
                ))}
              </select>
            </div>

            <button 
              className="btn-scan" 
              onClick={handleScan}
              disabled={loading}
            >
              {loading ? (
                <>
                  <div className="spinner-small"></div>
                  Scanning...
                </>
              ) : (
                <>
                  <RefreshCw size={18} />
                  Scan Resources
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        {/* Summary Section */}
        {summary && (
          <div className="summary-card">
            <h3>Scan Summary</h3>
            <div className="summary-grid">
              <div className="summary-item">
                <div className="summary-value">{summary.total_resources}</div>
                <div className="summary-label">Total Resources</div>
              </div>
              <div className="summary-item">
                <div className="summary-value">{summary.services_scanned}</div>
                <div className="summary-label">Services Scanned</div>
              </div>
              <div className="summary-item">
                <div className="summary-value">{summary.regions_scanned}</div>
                <div className="summary-label">Regions Scanned</div>
              </div>
              <div className="summary-item">
                <div className="summary-value">
                  {new Date(summary.timestamp).toLocaleTimeString()}
                </div>
                <div className="summary-label">Last Scan</div>
              </div>
            </div>
          </div>
        )}

        {/* Resources Section */}
        <div className="resources-grid">
          {Object.entries(resources).map(([serviceId, serviceResources]) => {
            const ServiceIcon = getServiceIcon(serviceId);
            const serviceName = services.find(s => s.id === serviceId)?.name || serviceId;
            
            return (
              <div key={serviceId} className="resource-card">
                <div className="resource-header">
                  <ServiceIcon size={24} />
                  <div>
                    <h4>{serviceName}</h4>
                    <span className="resource-count">
                      {serviceResources.length} resource{serviceResources.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                </div>

                <div className="resource-list">
                  {serviceResources.slice(0, 5).map((resource, index) => (
                    <div key={index} className="resource-item">
                      <div className="resource-id">
                        {resource.id || resource.name || resource.public_ip || 'N/A'}
                      </div>
                      <div className="resource-meta">
                        {resource.region && (
                          <span className="badge">{resource.region}</span>
                        )}
                        {resource.state && (
                          <span className={`badge badge-${resource.state}`}>
                            {resource.state}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                  
                  {serviceResources.length > 5 && (
                    <div className="resource-more">
                      +{serviceResources.length - 5} more
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {!loading && Object.keys(resources).length === 0 && !error && (
          <div className="empty-state">
            <Shield size={64} className="empty-icon" />
            <h3>No Resources Scanned Yet</h3>
            <p>Click "Scan Resources" to start scanning your AWS infrastructure</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;
