// SafeInbox - Gmail Email Extraction
class SafeInboxGmail {
  constructor() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
      return true;
    });
  }

  async handleMessage(request, _, sendResponse) {
    try {
      if (request.action === 'extractEmail') {
        const emailData = await this.extractCurrentEmailWithRetry();
        sendResponse({ success: true, emailData });
      } else if (request.action === 'checkGmailStatus') {
        const isOnGmail = window.location.hostname.includes('mail.google.com') || 
                         window.location.hostname.includes('gmail.com');
        sendResponse({ success: true, isOnGmail });
      } else {
        sendResponse({ error: 'Unknown action' });
      }
    } catch (error) {
      sendResponse({ error: error.message });
    }
  }

  async extractCurrentEmailWithRetry() {
    // Try extraction up to 3 times with short delays
    for (let attempt = 0; attempt < 3; attempt++) {
      const emailData = this.extractCurrentEmail();
      
      // If we got meaningful content, return it
      if (emailData.subject || (emailData.body && emailData.body.length > 20)) {
        console.log('SafeInbox: Email extraction successful on attempt', attempt + 1, emailData);
        return emailData;
      }
      
      // Wait a bit for Gmail to load content before retrying
      if (attempt < 2) {
        console.log('SafeInbox: Retrying email extraction, attempt', attempt + 2);
        await new Promise(resolve => setTimeout(resolve, 300));
      }
    }
    
    // Return whatever we got on the final attempt
    console.log('SafeInbox: Using final extraction attempt');
    return this.extractCurrentEmail();
  }

  extractCurrentEmail() {
    console.log('SafeInbox: Starting email extraction...');
    
    // Gmail's consistent DOM patterns for email content
    const subject = this.extractSubject();
    const from = this.extractFrom();
    const bodyData = this.extractBody();

    console.log('SafeInbox: Extraction results:', { 
      subject, 
      from, 
      bodyText: bodyData.bodyText.substring(0, 100) + '...',
      urlCount: bodyData.urls.length
    });
    
    return { 
      subject, 
      body: bodyData.bodyText, 
      urls: bodyData.urls,
      from 
    };
  }

  extractSubject() {
    // Gmail subject extraction - single method only
    const subjectElement = document.querySelector('h2.hP');
    if (subjectElement && this.isElementVisible(subjectElement)) {
      const subject = subjectElement.textContent.trim();
      console.log('SafeInbox: Subject found:', subject);
      return subject;
    }

    console.log('SafeInbox: No subject found');
    return '';
  }

  extractFrom() {
    // Gmail sender extraction - find any email span that's visible
    const emailSpans = document.querySelectorAll('span[email]');
    for (const span of emailSpans) {
      if (this.isElementVisible(span)) {
        const email = span.getAttribute('email');
        if (email && email.includes('@')) {
          console.log('SafeInbox: From found:', email);
          return email;
        }
      }
    }

    console.log('SafeInbox: No from address found');
    return '';
  }

  extractBody() {
    // Gmail body extraction - using the correct DOM structure from user's screenshot
    const bodyElement = document.querySelector('.a3s.aiL');
    if (bodyElement && this.isElementVisible(bodyElement)) {
      const clone = bodyElement.cloneNode(true);
      clone.querySelectorAll('.gmail_quote, .gmail_signature, .h5, .im').forEach(el => el.remove());
      
      // Extract URLs from anchor tags BEFORE converting to text
      const anchorUrls = [];
      const anchors = clone.querySelectorAll('a[href]');
      anchors.forEach(anchor => {
        const href = anchor.getAttribute('href');
        const linkText = anchor.textContent.trim();
        if (href && href.startsWith('http')) {
          anchorUrls.push(href);
          console.log('SafeInbox: Found anchor link:', linkText, '→', href);
        }
      });
      
      let bodyText = clone.textContent.trim();
      
      if (bodyText && bodyText.length > 20) {
        // Clean up extra spaces between words
        bodyText = bodyText.replace(/\s+/g, ' ').trim();
        
        // Extract plain text URLs from the body text
        const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
        const textUrls = bodyText.match(urlRegex) || [];
        
        // Combine anchor URLs and text URLs, removing duplicates
        const allUrls = [...new Set([...anchorUrls, ...textUrls])];
        
        console.log('SafeInbox: Body found, length:', bodyText.length);
        console.log('SafeInbox: CLEANED BODY TEXT:', bodyText);
        console.log('SafeInbox: ANCHOR URLs:', anchorUrls);
        console.log('SafeInbox: TEXT URLs:', textUrls);
        console.log('SafeInbox: ALL EXTRACTED URLs:', allUrls);
        console.log('SafeInbox: Total URLs found:', allUrls.length);
        
        return { bodyText, urls: allUrls };
      }
    }

    console.log('SafeInbox: No body found');
    return { bodyText: '', urls: [] };
  }

  isElementVisible(el) {
    return el.offsetParent !== null && 
           el.offsetWidth > 0 && 
           el.offsetHeight > 0 &&
           window.getComputedStyle(el).visibility !== 'hidden';
  }
}

// Initialize
new SafeInboxGmail();
