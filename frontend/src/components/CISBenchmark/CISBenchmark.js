// File: frontend/src/components/CISBenchmark/CISBenchmark.js

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, RefreshCw, Filter, CheckCircle,
  XCircle, AlertTriangle, Wrench, History, CheckSquare
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { cisAPI, resourcesAPI } from '../../services/api';
import Header from '../common/Header';
import './CISBenchmark.css';

function CISBenchmark({ sessionToken, onLogout }) {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [remediatingResources, setRemediatingResources] = useState(new Set());
  const [results, setResults] = useState({});
  const [summary, setSummary] = useState(null);
  const [selectedRegion, setSelectedRegion] = useState('all');
  const [selectedService, setSelectedService] = useState('all');
  const [regions, setRegions] = useState([]);
  const [services, setServices] = useState([]);
  const [error, setError] = useState('');
  const [expandedChecks, setExpandedChecks] = useState({});
  const [selectedResources, setSelectedResources] = useState({});

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
    setSelectedResources({});

    try {
      const region = selectedRegion === 'all' ? null : selectedRegion;
      const service = selectedService === 'all' ? null : selectedService;

      const response = await cisAPI.scan(sessionToken, region, service);
      setResults(response.data.results);
      setSummary(response.data.summary);
    } catch (err) {
      if (err.response?.status === 401) {
        setError('Session expired. Please login again.');
        setTimeout(() => {
          onLogout();
          navigate('/login');
        }, 2000);
      } else {
        setError(err.response?.data?.detail || 'Failed to scan CIS benchmarks');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleRemediateSingle = async (serviceId, checkId, resource) => {
    const resourceKey = `${serviceId}-${checkId}-${resource.resource_id}`;

    const confirmMessage = `Apply remediation for:\n\nCheck: ${checkId}\nResource: ${resource.resource_id}\nReason: ${resource.reason}\n\nThis will modify your AWS account.\n\nClick OK to proceed.`;

    if (!window.confirm(confirmMessage)) {
      return;
    }

    setRemediatingResources(prev => new Set(prev).add(resourceKey));

    try {
      // FIX: Correct region logic with proper parentheses
      const region = resource.region || (selectedRegion === 'all' ? 'us-east-1' : selectedRegion);

      console.log(`=== REMEDIATION REQUEST ===`);
      console.log(`Check ID: ${checkId}`);
      console.log(`Resource ID: ${resource.resource_id}`);
      console.log(`Region: ${region}`);
      console.log(`Resource Object:`, resource);

      const response = await cisAPI.remediate(sessionToken, region, checkId, [resource.resource_id]);

      console.log(`=== REMEDIATION RESPONSE ===`);
      console.log('Full Response:', response.data);

      // FIX: Better response handling
      if (response.data.details && response.data.details.length > 0) {
        const detail = response.data.details[0];
        
        console.log('Detail Object:', detail);
        
        if (detail.success) {
          alert(`✓ SUCCESS\n\nResource: ${detail.resource_id}\nMessage: ${detail.message}`);
          // Re-scan to refresh the results
          await handleScan();
        } else {
          alert(`✗ FAILED\n\nResource: ${detail.resource_id}\nMessage: ${detail.message}`);
        }
      } else if (response.data.success) {
        // Backend returned success but no details
        alert(`✓ SUCCESS\n\n${response.data.message || 'Remediation completed successfully'}`);
        await handleScan();
      } else {
        // Backend returned failure
        alert(`✗ FAILED\n\n${response.data.message || 'Remediation failed'}`);
      }
    } catch (err) {
      console.error('=== REMEDIATION ERROR ===');
      console.error('Error:', err);
      console.error('Response:', err.response);
      
      const errorMessage = err.response?.data?.detail || err.response?.data?.message || 'Remediation failed: ' + err.message;
      alert(`✗ FAILED\n\n${errorMessage}`);
    } finally {
      setRemediatingResources(prev => {
        const newSet = new Set(prev);
        newSet.delete(resourceKey);
        return newSet;
      });
    }
  };

  const handleRemediateSelected = async (serviceId, checkId, failedResources) => {
    const checkKey = `${serviceId}-${checkId}`;
    const selected = selectedResources[checkKey] || new Set();

    if (selected.size === 0) {
      alert('Please select at least one resource to remediate.');
      return;
    }

    const selectedResourcesList = failedResources.filter(r => selected.has(r.resource_id));

    const resourcesByRegion = {};
    selectedResourcesList.forEach(resource => {
      // FIX: Correct region logic
      const region = resource.region || (selectedRegion === 'all' ? 'us-east-1' : selectedRegion);

      if (!resourcesByRegion[region]) {
        resourcesByRegion[region] = [];
      }
      resourcesByRegion[region].push(resource);
    });

    const confirmMessage = `Apply remediation for ${selected.size} selected resource(s)?\n\nCheck: ${checkId}\nRegions: ${Object.keys(resourcesByRegion).join(', ')}\n\nClick OK to proceed.`;

    if (!window.confirm(confirmMessage)) {
      return;
    }

    setRemediatingResources(prev => {
      const newSet = new Set(prev);
      selectedResourcesList.forEach(r => newSet.add(`${serviceId}-${checkId}-${r.resource_id}`));
      return newSet;
    });

    try {
      let allResults = [];
      let successCount = 0;
      let failureMessages = [];

      console.log(`=== BULK REMEDIATION REQUEST ===`);
      console.log(`Check ID: ${checkId}`);
      console.log(`Resources by Region:`, resourcesByRegion);

      for (const [region, regionResources] of Object.entries(resourcesByRegion)) {
        const resourceIds = regionResources.map(r => r.resource_id);

        console.log(`Processing region ${region} with resources:`, resourceIds);

        try {
          const response = await cisAPI.remediate(sessionToken, region, checkId, resourceIds);

          console.log(`Region ${region} Response:`, response.data);

          if (response.data.details && response.data.details.length > 0) {
            const details = response.data.details;
            successCount += details.filter(d => d.success).length;
            allResults = allResults.concat(details);
            
            // Collect failure messages
            details.forEach(d => {
              if (!d.success) {
                failureMessages.push(`${d.resource_id}: ${d.message}`);
              }
            });
          } else if (response.data.success) {
            successCount += resourceIds.length;
          }
        } catch (err) {
          console.error(`Remediation failed for region ${region}:`, err);
          failureMessages.push(`Region ${region}: ${err.response?.data?.detail || err.message}`);
        }
      }

      let message = `Remediation Results:\n\n✓ ${successCount}/${selected.size} successful\n`;
      
      if (failureMessages.length > 0) {
        message += `\n❌ Failures:\n${failureMessages.slice(0, 5).join('\n')}`;
        if (failureMessages.length > 5) {
          message += `\n... and ${failureMessages.length - 5} more failures`;
        }
      }

      if (allResults.length > 0 && allResults.length <= 5) {
        message += `\n\nDetails:\n`;
        allResults.forEach(detail => {
          const status = detail.success ? '✓' : '✗';
          message += `${status} ${detail.resource_id}: ${detail.message}\n`;
        });
      }

      alert(message);

      setSelectedResources(prev => ({ ...prev, [checkKey]: new Set() }));
      if (successCount > 0) {
        await handleScan();
      }
    } catch (err) {
      console.error('=== BULK REMEDIATION ERROR ===', err);
      alert(`Remediation failed: ${err.message}`);
    } finally {
      setRemediatingResources(prev => {
        const newSet = new Set(prev);
        selectedResourcesList.forEach(r => newSet.delete(`${serviceId}-${checkId}-${r.resource_id}`));
        return newSet;
      });
    }
  };

  const toggleResourceSelection = (serviceId, checkId, resourceId) => {
    const checkKey = `${serviceId}-${checkId}`;
    setSelectedResources(prev => {
      const selected = new Set(prev[checkKey] || []);
      if (selected.has(resourceId)) {
        selected.delete(resourceId);
      } else {
        selected.add(resourceId);
      }
      return { ...prev, [checkKey]: selected };
    });
  };

  const toggleSelectAll = (serviceId, checkId, failedResources) => {
    const checkKey = `${serviceId}-${checkId}`;
    const selected = selectedResources[checkKey] || new Set();

    if (selected.size === failedResources.length) {
      setSelectedResources(prev => ({ ...prev, [checkKey]: new Set() }));
    } else {
      const allIds = new Set(failedResources.map(r => r.resource_id));
      setSelectedResources(prev => ({ ...prev, [checkKey]: allIds }));
    }
  };

  const toggleCheck = (serviceId, checkId) => {
    const key = `${serviceId}-${checkId}`;
    setExpandedChecks(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const COLORS = ['#48bb78', '#f56565'];

  const pieData = summary ? [
    { name: 'Passed', value: summary.total_passed },
    { name: 'Failed', value: summary.total_failed }
  ] : [];

  return (
    <div className="cis-benchmark">
      <Header
        title="CIS Benchmark Compliance"
        onLogout={() => {
          onLogout();
          navigate('/login');
        }}
        sessionToken={sessionToken}
      />

      <div className="cis-content">
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
                  Scan CIS Benchmarks
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-error">
            <AlertTriangle size={18} />
            {error}
          </div>
        )}

        {summary && (
          <>
            <div className="summary-cards-grid">
              <div className="summary-card-item passed">
                <CheckCircle size={32} />
                <div className="summary-card-content">
                  <div className="summary-card-value">{summary.total_passed}</div>
                  <div className="summary-card-label">Passed</div>
                </div>
              </div>

              <div className="summary-card-item failed">
                <XCircle size={32} />
                <div className="summary-card-content">
                  <div className="summary-card-value">{summary.total_failed}</div>
                  <div className="summary-card-label">Failed</div>
                </div>
              </div>

              <div className="summary-card-item compliance">
                <Shield size={32} />
                <div className="summary-card-content">
                  <div className="summary-card-value">{summary.compliance_percentage}%</div>
                  <div className="summary-card-label">Compliance</div>
                </div>
              </div>
            </div>

            <div className="charts-grid">
              <div className="chart-card">
                <h3>Compliance Overview</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, value }) => `${name}: ${value}`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </>
        )}

{Object.keys(results).length > 0 && (
          <div className="results-section">
            <h2>CIS Benchmark Results</h2>

            {/* Auto-Remediation Section */}
            <div className="benchmark-category">
              <div className="category-header auto-remediation">
                <Wrench size={24} />
                <div>
                  <h3>Automated Remediation Available</h3>
                  <p>These checks can be automatically remediated</p>
                </div>
              </div>

              {Object.entries(results).map(([serviceId, checks]) => {
                const autoRemediationChecks = [
                  'EBS_DEFAULT_ENCRYPTION',
                  'S3_BLOCK_PUBLIC_ACCESS',
                  'SNAPSHOT_PUBLIC',
                  'SG_SSH_OPEN',
                  'IAM_ACCESS_ANALYZER',
                  'EC2_UNTAGGED_INSTANCES'
                ];

                const autoChecks = Object.entries(checks).filter(([checkId]) =>
                  autoRemediationChecks.includes(checkId)
                );

                if (autoChecks.length === 0) return null;

                return (
                  <div key={`auto-${serviceId}`} className="service-results">
                    <h3 className="service-title">
                      {services.find(s => s.id === serviceId)?.name || serviceId.toUpperCase()}
                    </h3>

                    <div className="checks-list">
                      {autoChecks.map(([checkId, checkData]) => {
                        const isExpanded = expandedChecks[`${serviceId}-${checkId}`];
                        const hasFailed = checkData.failed > 0;
                        const checkKey = `${serviceId}-${checkId}`;
                        const selected = selectedResources[checkKey] || new Set();
                        const allSelected = selected.size === checkData.failed_resources.length &&
                          checkData.failed_resources.length > 0;

                        return (
                          <div key={checkId} className={`check-card ${hasFailed ? 'has-failures' : 'all-passed'}`}>
                            <div
                              className="check-header"
                              onClick={() => toggleCheck(serviceId, checkId)}
                            >
                              <div className="check-info">
                                {hasFailed ? (
                                  <XCircle size={20} className="icon-failed" />
                                ) : (
                                  <CheckCircle size={20} className="icon-passed" />
                                )}
                                <div>
                                  <div className="check-id">{checkId}</div>
                                  <div className="check-name">{checkData.name}</div>
                                </div>
                              </div>

                              <div className="check-stats">
                                <span className="stat-passed">✓ {checkData.passed}</span>
                                <span className="stat-failed">✗ {checkData.failed}</span>
                              </div>
                            </div>

                            {isExpanded && hasFailed && (
                              <div className="check-details">
                                <div className="failed-resources">
                                  <div className="resources-header">
                                    <h4>Failed Resources ({checkData.failed_resources.length})</h4>

                                    {checkData.failed_resources.length > 1 && (
                                      <div className="bulk-actions">
                                        <button
                                          className="btn-select-all"
                                          onClick={() => toggleSelectAll(serviceId, checkId, checkData.failed_resources)}
                                        >
                                          <CheckSquare size={14} />
                                          {allSelected ? 'Deselect All' : 'Select All'}
                                        </button>

                                        {selected.size > 0 && (
                                          <button
                                            className="btn-remediate-selected"
                                            onClick={() => handleRemediateSelected(serviceId, checkId, checkData.failed_resources)}
                                            disabled={remediatingResources.size > 0}
                                          >
                                            <Wrench size={14} />
                                            Remediate Selected ({selected.size})
                                          </button>
                                        )}
                                      </div>
                                    )}
                                  </div>

                                  <div className="resources-list">
                                    {checkData.failed_resources.map((resource, idx) => {
                                      const resourceKey = `${serviceId}-${checkId}-${resource.resource_id}`;
                                      const isRemediating = remediatingResources.has(resourceKey);
                                      const isSelected = selected.has(resource.resource_id);

                                      return (
                                        <div key={idx} className="failed-resource-item">
                                          {checkData.failed_resources.length > 1 && (
                                            <input
                                              type="checkbox"
                                              className="resource-checkbox"
                                              checked={isSelected}
                                              onChange={() => toggleResourceSelection(serviceId, checkId, resource.resource_id)}
                                              disabled={isRemediating}
                                            />
                                          )}

                                          <div className="resource-info">
                                            <strong>{resource.resource_id}</strong>
                                            <span className="resource-type">{resource.resource_type}</span>
                                            <span className="resource-reason">{resource.reason}</span>
                                            <span className="resource-region">Region: {resource.region}</span>
                                          </div>

                                          <button
                                            className="btn-remediate-single"
                                            onClick={() => handleRemediateSingle(serviceId, checkId, resource)}
                                            disabled={isRemediating}
                                            title="Remediate this resource"
                                          >
                                            {isRemediating ? (
                                              <>
                                                <div className="spinner-tiny"></div>
                                              </>
                                            ) : (
                                              <Wrench size={14} />
                                            )}
                                          </button>
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Manual Action Required Section */}
            <div className="benchmark-category">
              <div className="category-header manual-action">
                <AlertTriangle size={24} />
                <div>
                  <h3>Manual Action Required</h3>
                  <p>These checks require manual remediation due to security and data safety concerns</p>
                </div>
              </div>

              {Object.entries(results).map(([serviceId, checks]) => {
                const manualActionChecks = {
                  'EIP_ATTACHED': '⚠️ EIP is lost forever once released - Review before deleting',
                  'VOLUME_ORPHANED': '⚠️ May delete important backups - Manual review required',
                  'SG_OUTBOUND_UNRESTRICTED': '⚠️ May break all outbound connectivity - Manual configuration needed',
                  'IAM_ROOT_MFA': '🔒 Must configure MFA in AWS Console manually',
                  'VOLUME_ENCRYPTION': '📦 Must create encrypted snapshot and restore - Cannot encrypt existing volumes',
                  'SNAPSHOT_ENCRYPTION': '📦 Must create new encrypted snapshot - Cannot encrypt existing snapshots'
                };

                const manualChecks = Object.entries(checks).filter(([checkId]) =>
                  Object.keys(manualActionChecks).includes(checkId)
                );

                if (manualChecks.length === 0) return null;

                return (
                  <div key={`manual-${serviceId}`} className="service-results">
                    <h3 className="service-title manual">
                      {services.find(s => s.id === serviceId)?.name || serviceId.toUpperCase()}
                    </h3>

                    <div className="checks-list">
                      {manualChecks.map(([checkId, checkData]) => {
                        const isExpanded = expandedChecks[`${serviceId}-${checkId}`];
                        const hasFailed = checkData.failed > 0;

                        return (
                          <div key={checkId} className={`check-card manual ${hasFailed ? 'has-failures' : 'all-passed'}`}>
                            <div
                              className="check-header"
                              onClick={() => toggleCheck(serviceId, checkId)}
                            >
                              <div className="check-info">
                                {hasFailed ? (
                                  <AlertTriangle size={20} className="icon-warning" />
                                ) : (
                                  <CheckCircle size={20} className="icon-passed" />
                                )}
                                <div>
                                  <div className="check-id">{checkId}</div>
                                  <div className="check-name">{checkData.name}</div>
                                  <div className="manual-action-note">{manualActionChecks[checkId]}</div>
                                </div>
                              </div>

                              <div className="check-stats">
                                <span className="stat-passed">✓ {checkData.passed}</span>
                                <span className="stat-failed">✗ {checkData.failed}</span>
                              </div>
                            </div>

                            {isExpanded && hasFailed && (
                              <div className="check-details">
                                <div className="failed-resources">
                                  <h4>Failed Resources ({checkData.failed_resources.length})</h4>

                                  <div className="manual-action-banner">
                                    <AlertTriangle size={18} />
                                    <div>
                                      <strong>Manual Action Required</strong>
                                      <p>{manualActionChecks[checkId]}</p>
                                    </div>
                                  </div>

                                  <div className="resources-list">
                                    {checkData.failed_resources.map((resource, idx) => (
                                      <div key={idx} className="failed-resource-item manual">
                                        <div className="resource-info">
                                          <strong>{resource.resource_id}</strong>
                                          <span className="resource-type">{resource.resource_type}</span>
                                          <span className="resource-reason">{resource.reason}</span>
                                          <span className="resource-region">Region: {resource.region}</span>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {!loading && Object.keys(results).length === 0 && !error && (
          <div className="empty-state">
            <Shield size={64} className="empty-icon" />
            <h3>No CIS Benchmark Scan Yet</h3>
            <p>Click "Scan CIS Benchmarks" to start compliance checking</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default CISBenchmark;
