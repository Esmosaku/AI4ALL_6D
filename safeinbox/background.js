// SafeInbox - Background Service Worker
class SafeInboxBackground {
  constructor() {
    this.apiEndpoint = '';
    this.urlApiEndpoint = '';
    this.loadSettings();
    
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
      return true;
    });

    chrome.runtime.onInstalled.addListener(() => {
      chrome.storage.sync.set({ apiEndpoint: '', urlApiEndpoint: '' });
    });
  }

  async loadSettings() {
    try {
      const settings = await chrome.storage.sync.get([
        'apiEndpoint',
        'urlApiEndpoint'
      ]);
      
      // Use new unified API endpoint as default
      this.apiEndpoint = settings.apiEndpoint || 'http://localhost:5003/predict';
      this.urlApiEndpoint = settings.urlApiEndpoint || 'http://localhost:5003/predict';
      
      console.log('SafeInbox: Settings loaded - API endpoint:', this.apiEndpoint);
      console.log('SafeInbox: Settings loaded - URL API endpoint:', this.urlApiEndpoint);
    } catch (error) {
      console.error('SafeInbox: Failed to load settings:', error);
      // Use new unified API as fallback
      this.apiEndpoint = 'http://localhost:5003/predict';
      this.urlApiEndpoint = 'http://localhost:5003/predict';
    }
  }

  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case 'analyzeEmail':
          const result = await this.analyzeEmail(request.emailData);
          sendResponse({ success: true, result });
          break;
        case 'updateSettings':
          console.log('SafeInbox: Updating settings:', request.settings);
          await chrome.storage.sync.set(request.settings);
          this.apiEndpoint = request.settings.apiEndpoint || '';
          this.urlApiEndpoint = request.settings.urlApiEndpoint || '';
          console.log('SafeInbox: Settings updated:', {
            apiEndpoint: this.apiEndpoint,
            urlApiEndpoint: this.urlApiEndpoint
          });
          sendResponse({ success: true });
          break;
        case 'getSettings':
          const settings = await chrome.storage.sync.get({ apiEndpoint: '', urlApiEndpoint: '' });
          sendResponse({ success: true, settings });
          break;
        case 'testConnection':
          const testResult = await this.testConnection();
          sendResponse({ success: true, result: testResult });
          break;
        default:
          sendResponse({ error: 'Unknown action' });
      }
    } catch (error) {
      console.error('SafeInbox: Message handling error:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async analyzeEmail(emailData) {
    console.log('SafeInbox: Analyzing email and URLs via unified API...');
    
    // Analyze email content for phishing
    const emailResult = await this.analyzeEmailContent(emailData);
    
    // Analyze URLs if present
    let urlResults = [];
    if (emailData.urls && emailData.urls.length > 0) {
      console.log('SafeInbox: Analyzing', emailData.urls.length, 'URLs...');
      urlResults = await this.analyzeUrls(emailData.urls);
    }
    
    // Combine results using OR logic
    const hasPhishingUrl = urlResults.some(result => result.isPhishing);
    const phishingUrls = urlResults.filter(result => result.isPhishing);
    const safeUrls = urlResults.filter(result => !result.isPhishing);
    
    const finalResult = {
      isPhishing: emailResult.isPhishing || hasPhishingUrl,
      timestamp: new Date().toISOString(),
      source: emailResult.source,
      
      // Detailed breakdown
      emailAnalysis: {
        isPhishing: emailResult.isPhishing,
        confidence: emailResult.confidence || 0,
        source: emailResult.source
      },
      urlAnalysis: {
        totalUrls: urlResults.length,
        phishingUrls: phishingUrls.length,
        safeUrls: safeUrls.length,
        hasPhishing: hasPhishingUrl,
        results: urlResults
      },
      
      // Summary for display
      riskFactors: []
    };
    
    // Add risk factors
    if (emailResult.isPhishing) {
      finalResult.riskFactors.push('Email content flagged as phishing');
    }
    if (hasPhishingUrl) {
      finalResult.riskFactors.push(`${phishingUrls.length} malicious URL(s) detected`);
    }
    
    console.log('SafeInbox: Analysis complete:', finalResult);
    return finalResult;
  }

  async analyzeEmailContent(emailData) {
    console.log('SafeInbox: Email content analysis via API:', this.apiEndpoint);
    
    if (!this.apiEndpoint) {
      console.log('SafeInbox: No API endpoint configured, using mock analysis');
      return this.mockAnalysis(emailData);
    }

    try {
      console.log('SafeInbox: Calling unified API for email:', this.apiEndpoint);
      
      const response = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: emailData.subject || '',
          body: emailData.body || '',
          from: emailData.from || ''
        })
      });

      if (!response.ok) throw new Error(`API Error: ${response.status}`);
      
      const data = await response.json();
      console.log('SafeInbox: Email API response:', data);
      
      return {
        isPhishing: data.isPhishing || data.prediction === 1,
        confidence: data.confidence || 0,
        source: 'API',
        timestamp: data.timestamp
      };
      
    } catch (error) {
      console.error('SafeInbox: Email API failed:', error);
      console.log('SafeInbox: Falling back to mock analysis');
      return this.mockAnalysis(emailData);
    }
  }

  async analyzeUrls(urls) {
    if (!this.urlApiEndpoint) {
      console.log('SafeInbox: No URL API configured, skipping URL analysis');
      return [];
    }

    const results = [];
    
    for (const url of urls) {
      try {
        console.log('SafeInbox: Analyzing URL:', url);
        
        const response = await fetch(this.urlApiEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error(`URL API Error: ${response.status}`);
        
        const data = await response.json();
        console.log('SafeInbox: URL API response for', url, ':', data);
        
        results.push({
          url: url,
          isPhishing: data.isPhishing || data.prediction === 1,
          confidence: data.confidence || 0,
          source: 'API',
          timestamp: data.timestamp
        });
        
      } catch (error) {
        console.error('SafeInbox: URL analysis failed for', url, ':', error);
        // Add as unknown/safe by default if API fails
        results.push({
          url: url,
          isPhishing: false,
          confidence: 0,
          source: 'Error',
          error: error.message
        });
      }
    }
    
    return results;
  }

  normalizeResponse(apiResponse) {
    const isPhishing = typeof apiResponse === 'number' 
      ? apiResponse === 1
      : apiResponse?.isPhishing || 
        [apiResponse?.prediction, apiResponse?.result, apiResponse?.label]
          .some(val => val === 1 || val === 'phishing');

    return { isPhishing, timestamp: new Date().toISOString(), source: 'api' };
  }

  mockAnalysis(emailData) {
    const text = `${emailData.subject} ${emailData.body} ${emailData.from}`.toLowerCase();
    
    const phishingIndicators = [
      'urgent', 'immediate', 'verify', 'suspended', 'expires', 'click here',
      'update payment', 'confirm account', 'limited time', 'act now', 'winner',
      'congratulations', 'refund', 'bitcoin', 'within 24 hours', 'expires today',
      'account will be closed', 'verify now', 'http://', 'bit.ly', 'tinyurl', '!!'
    ];

    let score = 0;
    phishingIndicators.forEach(indicator => {
      if (text.includes(indicator)) score += 0.1;
    });

    return {
      isPhishing: score >= 0.5,
      timestamp: new Date().toISOString(),
      source: 'mock'
    };
  }

  async testConnection() {
    const results = { email: null, url: null };
    
    // Test email API
    if (this.apiEndpoint) {
      try {
        // Build health URL more robustly
        let healthUrl = this.apiEndpoint;
        if (healthUrl.endsWith('/predict')) {
          healthUrl = healthUrl.replace('/predict', '/health');
        } else {
          // If URL doesn't end with /predict, try to build health URL
          const baseUrl = healthUrl.replace(/\/+$/, ''); // Remove trailing slashes
          healthUrl = `${baseUrl}/health`;
        }
        
        console.log('SafeInbox: Testing health endpoint:', healthUrl);
        
        const response = await fetch(healthUrl, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
          const data = await response.json();
          results.email = { 
            success: true, 
            message: data.email_model_loaded ? 'Email model ready' : 'Email model not loaded',
            healthy: data.email_model_loaded
          };
        } else {
          results.email = { success: false, message: `HTTP ${response.status}` };
        }
      } catch (error) {
        console.error('SafeInbox: Health check failed:', error);
        results.email = { success: false, message: error.message };
      }
    }
    
    // Test URL API (check if it's the same endpoint)
    if (this.urlApiEndpoint && this.urlApiEndpoint !== this.apiEndpoint) {
      try {
        // Build health URL more robustly
        let healthUrl = this.urlApiEndpoint;
        if (healthUrl.endsWith('/predict')) {
          healthUrl = healthUrl.replace('/predict', '/health');
        } else {
          const baseUrl = healthUrl.replace(/\/+$/, ''); // Remove trailing slashes
          healthUrl = `${baseUrl}/health`;
        }
        
        console.log('SafeInbox: Testing URL health endpoint:', healthUrl);
        
        const response = await fetch(healthUrl, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
          const data = await response.json();
          results.url = { 
            success: true, 
            message: data.url_model_loaded ? 'URL model ready' : 'URL model not loaded',
            healthy: data.url_model_loaded
          };
        } else {
          results.url = { success: false, message: `HTTP ${response.status}` };
        }
      } catch (error) {
        console.error('SafeInbox: URL health check failed:', error);
        results.url = { success: false, message: error.message };
      }
    } else if (this.urlApiEndpoint === this.apiEndpoint && results.email) {
      // Same endpoint, copy email results
      results.url = {
        success: results.email.success,
        message: results.email.success ? 'URL model ready (unified API)' : results.email.message,
        healthy: results.email.healthy
      };
    }
    
    return { success: true, results };
  }
}

// Initialize
new SafeInboxBackground();
