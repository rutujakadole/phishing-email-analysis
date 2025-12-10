# phishing-email-analysis
Task 2 – Phishing Email Analysis

Cyber Security Internship – Task 2

- Objective

  To analyze a phishing email sample and identify red flags such as spoofed sender addresses, malicious links, deceptive content, header inconsistencies, and social engineering techniques. The goal is to gain hands-on experience in email threat detection.

- Tools Used

  Email sample (email_sample.txt)
  
  Online email header analyzer
  (https://mxtoolbox.com/EmailHeaders.aspx
  )
  
  Screenshot annotations
  
  Browser (for safe URL preview – no clicking)

- Steps Performed
  1. Reviewed the Phishing Email Sample
  
      The phishing email (visible in phishing_email.png) pretends to be from a trusted service and claims there is “unusual login activity,” prompting the user to verify their account.
      
      Red flags observed:
      
      SuspiciousFrom: address
      
      Urgent, threatening language
      
      Grammar issues
      
      Fake security warnings
      
      Mismatched URL preview
  
  2. Extracted and Analyzed Email Headers
  
      Copied the header section from the email sample and uploaded it to MXToolbox’s Email Header Analyzer.
      
      Screenshot included: analysis.png
      
      Findings:
      
      SPF: FAIL
      
      DKIM: none
      
      DMARC: FAIL
      
      Email originated from an unknown mail server
      
      “Return-Path” does not match the “From” address
      
      Domain not associated with the real brand
      
      Clear signs of spoofing
      
      These inconsistencies confirm this is not a legitimate email sender.
  
  3. Inspected URLs Safely
  
      Hovering over the “Verify Now” button (screenshot: maliciouslink.png) shows:
      
      Display URL:
      https://paypal.com/security/update
      
      Actual hidden URL:
      http://paypal-verification-alert-security.com/login
      
      Red Flags:
      
      Completely different domain
      
      Uses http:// instead of HTTPS
      
      Domain appears newly created
      
      Typical phishing domain structure (brand-name + security + alert + random words)

- Summary of Phishing Indicators
  Sender Issues ->	Fake domain, spoofed display name
  Header Issues ->	SPF/DKIM/DMARC fails, Return-Path mismatch
  URL Manipulation ->	Hover URL does not match displayed URL
  Social Engineering ->	Urgency, scare tactics, account suspension
  Greeting Format ->	Generic greeting (“Dear Customer”)
  Grammar Mistakes ->	Unprofessional language


- Risk Assessment

  If a user interacts with this phishing email:
  
  Their login credentials may be stolen
  
  The attacker could perform account takeover
  
  Device may be infected if attachments existed
  
  Sensitive information may be compromised
  
  Further targeted attacks could follow

- Included Files

  email_sample.txt – complete phishing email text + fake headers
  
  phishing_email.png – screenshot of email body
  
  analysis.png – screenshot of header analyzer results
  
  maliciouslink.png – screenshot showing malicious link preview
