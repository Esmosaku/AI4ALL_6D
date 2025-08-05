// SafeInbox - Popup Interface
class SafeInboxPopup {
  constructor() {
    this.isScanning = false;
    this.SCAN_BUTTON_HTML = `
      Scan Current Email
    `;
    this.init();
  }

  init() {
    // Initialize components
    document.getElementById('scanButton').addEventListener('click', () => this.scanCurrentEmail());
    
    const settingsToggle = document.getElementById('settingsToggle');
    const settingsContent = document.getElementById('settingsContent');
    
    settingsToggle.addEventListener('click', () => {
      const isVisible = settingsContent.style.display !== 'none';
      settingsContent.style.display = isVisible ? 'none' : 'block';
      settingsToggle.querySelector('svg').style.transform = isVisible ? 'rotate(0deg)' : 'rotate(180deg)';
    });
    
    settingsContent.style.display = 'none';
    
    document.getElementById('saveSettings').addEventListener('click', () => this.saveSettings());
    document.getElementById('testConnection').addEventListener('click', () => this.testConnection());
    
    this.loadSettings();
    this.checkGmailTab();
  }

  async checkGmailTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const currentTab = tabs[0];
      const isGmail = currentTab.url && (
        currentTab.url.includes('mail.google.com') || 
        currentTab.url.includes('gmail.com')
      );
      
      const scanButton = document.getElementById('scanButton');
      const instructionText = document.getElementById('instructionText');
      
      if (isGmail) {
        scanButton.disabled = false;
        instructionText.textContent = 'Open an email in Gmail and click scan to check for phishing.';
      } else {
        scanButton.disabled = true;
        instructionText.textContent = 'Please open Gmail to use the phishing scanner.';
      }
    } catch (error) {
      console.error('Error checking Gmail tab:', error);
      // Default to disabled if we can't check
      document.getElementById('scanButton').disabled = true;
      document.getElementById('instructionText').textContent = 'Please open Gmail to use the phishing scanner.';
    }
  }

  async scanCurrentEmail() {
    if (this.isScanning) return;
    
    const scanButton = document.getElementById('scanButton');
    const scanResult = document.getElementById('scanResult');
    const instructionText = document.getElementById('instructionText');
    
    this.isScanning = true;
    scanButton.disabled = true;
    scanButton.textContent = 'Scanning...';
    scanResult.innerHTML = '';
    instructionText.textContent = 'Extracting email content...';
    
    try {
      // Check Gmail status and extract email
      const gmailStatus = await this.sendMessageToTab({ action: 'checkGmailStatus' });
      if (!gmailStatus.success || !gmailStatus.isOnGmail) {
        throw new Error('Please open Gmail and navigate to an email first');
      }
      
      // Add a small delay to ensure Gmail has fully loaded the email content
      instructionText.textContent = 'Waiting for email to load...';
      await new Promise(resolve => setTimeout(resolve, 500));
      
      instructionText.textContent = 'Extracting email content...';
      const extractResult = await this.sendMessageToTab({ action: 'extractEmail' });
      if (!extractResult.success) {
        throw new Error('Failed to extract email content');
      }
      
      const emailData = extractResult.emailData;
      if (!emailData.subject && !emailData.body) {
        throw new Error('No email content found. Please open an email in Gmail first.');
      }
      
      // Analyze email
      instructionText.textContent = 'Analyzing email for phishing...';
      const analysisResult = await this.sendMessage({ action: 'analyzeEmail', emailData });
      if (!analysisResult.success) {
        throw new Error('Analysis failed');
      }
      
      this.displayScanResult(analysisResult.result, emailData);
      instructionText.textContent = 'Scan complete! Open another email to scan again.';
      
    } catch (error) {
      this.displayError(error.message);
      instructionText.textContent = error.message;
    } finally {
      this.isScanning = false;
      scanButton.disabled = false;
      scanButton.innerHTML = this.SCAN_BUTTON_HTML;
    }
  }

  displayScanResult(result, emailData) {
    const scanResult = document.getElementById('scanResult');
    
    const isPhishing = result.isPhishing;
    const bgColor = isPhishing ? '#fff2f0' : '#f6ffed';
    const borderColor = isPhishing ? '#ffccc7' : '#b7eb8f';
    const iconColor = isPhishing ? '#ff4d4f' : '#52c41a';
    const statusText = isPhishing ? 'Phising Detected' : 'Email Looks Safe';
    const icon = isPhishing ? '⚠' : '✓';
    
    let detailsHtml = '';
    
    // Email content analysis
    if (result.emailAnalysis) {
      const emailStatus = result.emailAnalysis.isPhishing ? 'Phishing' : 'Safe';
      const emailIcon = result.emailAnalysis.isPhishing ? '🚨' : '✓';
      const confidence = Math.round((result.emailAnalysis.confidence || 0) * 100);
      
      detailsHtml += `
        <div class="analysis-section">
          <h4>Email Content Analysis</h4>
          <div class="analysis-item">
            ${emailIcon} <strong>${emailStatus}</strong> (${confidence}% confidence)
          </div>
        </div>
      `;
    }
    
    // URL analysis
    if (result.urlAnalysis && result.urlAnalysis.totalUrls > 0) {
      detailsHtml += `
        <div class="analysis-section">
          <h4>URL Analysis</h4>
          <div class="url-summary">
            <div class="analysis-item">Total URLs found: <strong>${result.urlAnalysis.totalUrls}</strong></div>
            <div class="analysis-item">Safe URLs: <strong>${result.urlAnalysis.safeUrls}</strong></div>
            <div class="analysis-item">Malicious URLs: <strong>${result.urlAnalysis.phishingUrls}</strong></div>
          </div>
      `;
      
      // Show individual URL results
      if (result.urlAnalysis.results && result.urlAnalysis.results.length > 0) {
        detailsHtml += '<div class="url-details">';
        
        result.urlAnalysis.results.forEach(urlResult => {
          const urlIcon = urlResult.isPhishing ? '🚨' : '✓';
          const urlStatus = urlResult.isPhishing ? 'Malicious' : 'Safe';
          const urlConfidence = Math.round((urlResult.confidence || 0) * 100);
          const shortUrl = urlResult.url.length > 50 ? 
            urlResult.url.substring(0, 47) + '...' : urlResult.url;
          
          // Show warning flags if available
          let warningText = '';
          if (urlResult.warning_flags && urlResult.warning_flags.length > 0) {
            warningText = `<div class="url-warnings">⚠ ${urlResult.warning_flags.join(', ')}</div>`;
          }
          
          detailsHtml += `
            <div class="url-item">
              <div class="url-status">${urlIcon} <strong>${urlStatus}</strong> (${urlConfidence}%)</div>
              <div class="url-link" title="${urlResult.url}">${shortUrl}</div>
              ${warningText}
            </div>
          `;
        });
        
        detailsHtml += '</div>';
      }
      
      detailsHtml += '</div>';
    } else if (result.urlAnalysis && result.urlAnalysis.totalUrls === 0) {
      detailsHtml += `
        <div class="analysis-section">
          <h4>URL Analysis</h4>
          <div class="analysis-item">No URLs found in email</div>
        </div>
      `;
    }
    
    // Risk factors summary
    if (result.riskFactors && result.riskFactors.length > 0) {
      detailsHtml += `
        <div class="analysis-section">
          <h4>Risk Factors Detected</h4>
          ${result.riskFactors.map(factor => `
            <div class="risk-factor">${factor}</div>
          `).join('')}
        </div>
      `;
    }
    
    // Email content preview
    const subject = emailData.subject || 'No subject';
    const bodyPreview = emailData.body ? 
      (emailData.body.length > 100 ? emailData.body.substring(0, 97) + '...' : emailData.body) : 
      'No content';
    
    scanResult.innerHTML = `
      <div class="result-card" style="background: ${bgColor}; border-color: ${borderColor};">
        <div class="result-header">
          <span class="result-icon" style="color: ${iconColor};">${icon}</span>
          <h3 class="result-title">${statusText}</h3>
        </div>
        
        <div class="email-preview">
          <div class="email-info">
            <div><strong>Subject:</strong> ${subject}</div>
            <div><strong>Content:</strong> ${bodyPreview}</div>
          </div>
        </div>
        
        ${detailsHtml}
        
        <div class="timestamp">
          Scanned: ${new Date(result.timestamp).toLocaleString()}
        </div>
      </div>
    `;
  }

  displayError(errorMessage) {
    document.getElementById('scanResult').innerHTML = `
      <div class="scan-result error">
        <div class="result-header">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="#ea4335">
            <path d="M1 21H23L12 2L1 21ZM13 18H11V16H13V18ZM13 14H11V10H13V14Z"/>
          </svg>
          <span class="result-title">Scan Failed</span>
        </div>
        <div class="result-details">
          <p>${this.escapeHtml(errorMessage)}</p>
        </div>
      </div>
    `;
  }

  async loadSettings() {
    try {
      const response = await this.sendMessage({ action: 'getSettings' });
      if (response.success && response.settings) {
        const emailEndpoint = response.settings.apiEndpoint || '';
        const urlEndpoint = response.settings.urlApiEndpoint || '';
        
        document.getElementById('apiEndpoint').value = emailEndpoint;
        document.getElementById('urlApiEndpoint').value = urlEndpoint;
        
        console.log('Settings loaded:', { emailEndpoint, urlEndpoint });
      } else {
        console.log('No saved settings found, using defaults');
      }
    } catch (error) {
      console.error('Error loading settings:', error);
      // Set default empty values if loading fails
      document.getElementById('apiEndpoint').value = '';
      document.getElementById('urlApiEndpoint').value = '';
    }
  }

  async saveSettings() {
    const saveButton = document.getElementById('saveSettings');
    const saveResult = document.getElementById('saveResult');
    
    saveButton.disabled = true;
    saveButton.textContent = 'Saving...';
    
    try {
      const emailEndpoint = document.getElementById('apiEndpoint').value.trim();
      const urlEndpoint = document.getElementById('urlApiEndpoint').value.trim();
      
      // Validate that at least one endpoint is provided
      if (!emailEndpoint && !urlEndpoint) {
        this.showResult(saveResult, 'Please provide at least one API endpoint', 'error');
        return;
      }
      
      const settings = {
        apiEndpoint: emailEndpoint,
        urlApiEndpoint: urlEndpoint
      };

      const response = await this.sendMessage({ action: 'updateSettings', settings });
      
      if (response.success) {
        this.showResult(saveResult, 'Settings saved successfully!', 'success');
      } else {
        this.showResult(saveResult, 'Error saving settings', 'error');
      }
    } catch (error) {
      console.error('Save settings error:', error);
      this.showResult(saveResult, 'Error saving settings: ' + error.message, 'error');
    } finally {
      saveButton.disabled = false;
      saveButton.textContent = 'Save';
    }
  }

  async testConnection() {
    const testButton = document.getElementById('testConnection');
    const connectionResult = document.getElementById('connectionResult');
    
    testButton.disabled = true;
    testButton.textContent = 'Testing...';
    this.showResult(connectionResult, 'Testing connection...', 'testing');
    
    try {
      const emailEndpoint = document.getElementById('apiEndpoint').value.trim();
      const urlEndpoint = document.getElementById('urlApiEndpoint').value.trim();
      
      // Validate that at least one endpoint is provided
      if (!emailEndpoint && !urlEndpoint) {
        this.showResult(connectionResult, 'Please provide at least one API endpoint to test', 'error');
        return;
      }
      
      // Save settings first
      const settings = {
        apiEndpoint: emailEndpoint,
        urlApiEndpoint: urlEndpoint
      };
      await this.sendMessage({ action: 'updateSettings', settings });
      
      const response = await this.sendMessage({ action: 'testConnection' });
      
      if (response.success && response.result.success) {
        this.displayConnectionResult(response.result);
      } else {
        const errorMsg = response.result.message || response.result.error || 'Connection failed';
        this.showResult(connectionResult, errorMsg, 'error');
      }
    } catch (error) {
      console.error('Test connection error:', error);
      this.showResult(connectionResult, `Connection failed: ${error.message}`, 'error');
    } finally {
      testButton.disabled = false;
      testButton.textContent = 'Test';
      setTimeout(() => connectionResult.style.display = 'none', 8000);
    }
  }

  showResult(element, message, type) {
    element.textContent = message;
    element.className = `${element.className.split(' ')[0]} ${type}`;
    element.style.display = 'block';
    if (type === 'success' || type === 'error') {
      setTimeout(() => element.style.display = 'none', 3000);
    }
  }

  sendMessage(message) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, resolve);
    });
  }

  sendMessageToTab(message) {
    return new Promise((resolve, reject) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length === 0) return reject(new Error('No active tab found'));
        chrome.tabs.sendMessage(tabs[0].id, message, (response) => {
          chrome.runtime.lastError ? reject(new Error(chrome.runtime.lastError.message)) : resolve(response);
        });
      });
    });
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  displayConnectionResult(result) {
    const connectionResult = document.getElementById('connectionResult');
    
    if (result.success) {
      const { email, url } = result.results;
      let html = '<div class="connection-success">Connection Test Results:</div>';
      
      if (email) {
        const emailStatus = email.success && email.healthy ? 'Ready' : 
                          email.success ? 'Connected (model issue)' : 'Failed';
        html += `<div class="api-result">Email API: ${emailStatus}</div>`;
        if (email.message) html += `<div class="api-message">${email.message}</div>`;
      }
      
      if (url) {
        const urlStatus = url.success && url.healthy ? 'Ready' : 
                         url.success ? 'Connected (model issue)' : 'Failed';
        html += `<div class="api-result">URL API: ${urlStatus}</div>`;
        if (url.message) html += `<div class="api-message">${url.message}</div>`;
      }
      
      connectionResult.innerHTML = html;
      connectionResult.className = 'connection-result success';
    } else {
      connectionResult.innerHTML = `<div class="connection-error">${result.error || 'Connection failed'}</div>`;
      connectionResult.className = 'connection-result error';
    }
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => new SafeInboxPopup());
