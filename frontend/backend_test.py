#!/usr/bin/env python3
"""
Backend API tests for VibeSafe Priority 2 + Priority 3 features.
Tests Turnstile, rate limiting, waitlist, static files, and regressions.
Uses unique IPs per test scenario to avoid rate-limit pollution.
"""

import requests
import json
import os
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_URL = os.getenv('NEXT_PUBLIC_BASE_URL', 'https://vibesafe-marketing.preview.emergentagent.com')
API_BASE = f"{BASE_URL}/api"

print(f"Testing API at: {API_BASE}\n")
print("=" * 80)

# Track test results
passed = 0
failed = 0
test_results = []

def test_result(name, success, message=""):
    global passed, failed
    if success:
        passed += 1
        status = "✅ PASS"
    else:
        failed += 1
        status = "❌ FAIL"
    result = f"{status}: {name}"
    if message:
        result += f" - {message}"
    print(result)
    test_results.append((name, success, message))
    return success

# ============================================================================
# 1) POST /api/scan/github — Turnstile + rate limit
# ============================================================================

print("\n" + "=" * 80)
print("1. POST /api/scan/github — Turnstile + rate limit")
print("=" * 80)

# Test 1.1: Valid request with turnstile token
print("\n1.1. Valid request with turnstile token")
print("-" * 80)
try:
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "turnstile_token": "XXXX.DUMMY.TOKEN.XXXX"
    }
    headers = {"x-forwarded-for": "203.0.113.1"}
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Valid request with token returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Response has ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    
    scan_id = data.get('scan_id', '')
    test_result("scan_id starts with 'vs_'", scan_id.startswith('vs_'), f"Got {scan_id}")
    
    # Verify GET /api/scan/:id still works
    if scan_id.startswith('vs_'):
        get_response = requests.get(f"{API_BASE}/scan/{scan_id}", timeout=10)
        test_result("GET /api/scan/:id works after POST", get_response.status_code == 200, f"Got {get_response.status_code}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Valid request with token", False, str(e))
    print(f"Error: {e}")

# Test 1.2: Request without turnstile_token (empty string)
print("\n1.2. Request without turnstile_token (empty string)")
print("-" * 80)
try:
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "turnstile_token": ""
    }
    headers = {"x-forwarded-for": "203.0.113.2"}
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Empty turnstile_token returns 400", response.status_code == 400, f"Got {response.status_code}")
    test_result("Error message contains 'Captcha'", 'captcha' in data.get('error', '').lower(), f"Got: {data.get('error')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Empty turnstile_token", False, str(e))
    print(f"Error: {e}")

# Test 1.3: Request without turnstile_token (missing field)
print("\n1.3. Request without turnstile_token (missing field)")
print("-" * 80)
try:
    payload = {
        "repo_url": "https://github.com/vercel/next.js"
    }
    headers = {"x-forwarded-for": "203.0.113.3"}
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Missing turnstile_token returns 400", response.status_code == 400, f"Got {response.status_code}")
    test_result("Error message contains 'Captcha'", 'captcha' in data.get('error', '').lower(), f"Got: {data.get('error')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Missing turnstile_token", False, str(e))
    print(f"Error: {e}")

# Test 1.4: Invalid repo_url without turnstile_token (URL validation runs BEFORE turnstile)
print("\n1.4. Invalid repo_url without turnstile_token")
print("-" * 80)
try:
    payload = {
        "repo_url": "not-a-valid-url"
    }
    headers = {"x-forwarded-for": "203.0.113.4"}
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Invalid URL returns 400", response.status_code == 400, f"Got {response.status_code}")
    test_result("Error is URL validation (not Captcha)", 'github' in data.get('error', '').lower() or 'url' in data.get('error', '').lower(), f"Got: {data.get('error')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Invalid URL without token", False, str(e))
    print(f"Error: {e}")

# Test 1.5: Rate limit - 5 requests from same IP
print("\n1.5. Rate limit - 5 requests from same IP (198.51.100.7)")
print("-" * 80)
try:
    ip = "198.51.100.7"
    headers = {"x-forwarded-for": ip}
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "turnstile_token": "VALID.TOKEN.HERE"
    }
    
    # Send 5 requests
    for i in range(5):
        response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
        test_result(f"Request {i+1}/5 returns 200", response.status_code == 200, f"Got {response.status_code}")
        time.sleep(0.2)  # Small delay between requests
    
    # 6th request should be rate limited
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("6th request returns 429", response.status_code == 429, f"Got {response.status_code}")
    test_result("Response has ok: false", data.get('ok') == False, f"Got {data.get('ok')}")
    test_result("Error contains 'Slow down'", 'slow down' in data.get('error', '').lower(), f"Got: {data.get('error')}")
    test_result("Error contains '5 scans per hour'", '5' in data.get('error', '') and 'hour' in data.get('error', '').lower(), f"Got: {data.get('error')}")
    
    retry_after = data.get('retry_after_seconds', 0)
    test_result("retry_after_seconds is positive", isinstance(retry_after, (int, float)) and retry_after > 0, f"Got {retry_after}")
    
    retry_header = response.headers.get('Retry-After', '')
    test_result("Retry-After header present", retry_header != '', f"Got: {retry_header}")
    test_result("Retry-After header matches retry_after_seconds", str(retry_after) == retry_header or int(retry_header) == int(retry_after), f"Body: {retry_after}, Header: {retry_header}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
    print(f"Retry-After header: {retry_header}")
except Exception as e:
    test_result("Rate limit test", False, str(e))
    print(f"Error: {e}")

# Test 1.6: Different IP has independent quota
print("\n1.6. Different IP (198.51.100.8) has independent quota")
print("-" * 80)
try:
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "turnstile_token": "VALID.TOKEN.HERE"
    }
    headers = {"x-forwarded-for": "198.51.100.8"}
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Different IP returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Different IP has ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Different IP independent quota", False, str(e))
    print(f"Error: {e}")

# Test 1.7: Honeypot with turnstile_token
print("\n1.7. Honeypot with turnstile_token")
print("-" * 80)
try:
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "website": "spam",
        "turnstile_token": "ignored"
    }
    headers = {"x-forwarded-for": "203.0.113.5"}
    response = requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Honeypot returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Honeypot returns ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    test_result("Honeypot returns scan_id: 'ignored'", data.get('scan_id') == 'ignored', f"Got {data.get('scan_id')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Honeypot with token", False, str(e))
    print(f"Error: {e}")

# ============================================================================
# 2) POST /api/waitlist — MongoDB persistence
# ============================================================================

print("\n" + "=" * 80)
print("2. POST /api/waitlist — MongoDB persistence")
print("=" * 80)

# Test 2.1: Valid email with source
print("\n2.1. Valid email with source='footer'")
print("-" * 80)
try:
    payload = {
        "email": "alice@example.com",
        "source": "footer"
    }
    headers = {"x-forwarded-for": "203.0.113.10"}
    response = requests.post(f"{API_BASE}/waitlist", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Valid email returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Response has ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    test_result("Response email matches", data.get('email') == 'alice@example.com', f"Got {data.get('email')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Valid email with source", False, str(e))
    print(f"Error: {e}")

# Test 2.2: Email is lowercased
print("\n2.2. Email is lowercased (ALICE@EXAMPLE.COM)")
print("-" * 80)
try:
    payload = {
        "email": "ALICE@EXAMPLE.COM",
        "source": "scan"
    }
    headers = {"x-forwarded-for": "203.0.113.11"}
    response = requests.post(f"{API_BASE}/waitlist", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Uppercase email returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Email is lowercased", data.get('email') == 'alice@example.com', f"Got {data.get('email')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Email lowercasing", False, str(e))
    print(f"Error: {e}")

# Test 2.3: Invalid email
print("\n2.3. Invalid email")
print("-" * 80)
try:
    payload = {
        "email": "not-an-email"
    }
    headers = {"x-forwarded-for": "203.0.113.12"}
    response = requests.post(f"{API_BASE}/waitlist", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Invalid email returns 400", response.status_code == 400, f"Got {response.status_code}")
    test_result("Response has ok: false", data.get('ok') == False, f"Got {data.get('ok')}")
    test_result("Error message present", 'error' in data, f"Got: {data.get('error')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Invalid email", False, str(e))
    print(f"Error: {e}")

# Test 2.4: Honeypot
print("\n2.4. Honeypot (website field)")
print("-" * 80)
try:
    payload = {
        "email": "x@y.co",
        "website": "bot"
    }
    headers = {"x-forwarded-for": "203.0.113.13"}
    response = requests.post(f"{API_BASE}/waitlist", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("Honeypot returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Honeypot returns ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Honeypot", False, str(e))
    print(f"Error: {e}")

# Test 2.5: Rate limit - 3 per hour per IP
print("\n2.5. Rate limit - 3 requests from same IP (203.0.113.20)")
print("-" * 80)
try:
    ip = "203.0.113.20"
    headers = {"x-forwarded-for": ip}
    
    # Send 3 requests with different emails
    for i in range(3):
        payload = {
            "email": f"user{i}@example.com",
            "source": "test"
        }
        response = requests.post(f"{API_BASE}/waitlist", json=payload, headers=headers, timeout=10)
        test_result(f"Request {i+1}/3 returns 200", response.status_code == 200, f"Got {response.status_code}")
        time.sleep(0.2)
    
    # 4th request should be rate limited
    payload = {
        "email": "user3@example.com",
        "source": "test"
    }
    response = requests.post(f"{API_BASE}/waitlist", json=payload, headers=headers, timeout=10)
    data = response.json()
    
    test_result("4th request returns 429", response.status_code == 429, f"Got {response.status_code}")
    test_result("Response has ok: false", data.get('ok') == False, f"Got {data.get('ok')}")
    
    retry_after = data.get('retry_after_seconds', 0)
    test_result("retry_after_seconds is positive", isinstance(retry_after, (int, float)) and retry_after > 0, f"Got {retry_after}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Waitlist rate limit", False, str(e))
    print(f"Error: {e}")

# ============================================================================
# 3) GET /api/rate-limit/:endpoint
# ============================================================================

print("\n" + "=" * 80)
print("3. GET /api/rate-limit/:endpoint")
print("=" * 80)

# Test 3.1: Fresh IP quota check
print("\n3.1. GET /api/rate-limit/scan/github from fresh IP")
print("-" * 80)
try:
    headers = {"x-forwarded-for": "203.0.113.99"}
    response = requests.get(f"{API_BASE}/rate-limit/scan/github", headers=headers, timeout=10)
    data = response.json()
    
    test_result("Rate limit check returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Response has ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    test_result("endpoint is 'scan/github'", data.get('endpoint') == 'scan/github', f"Got {data.get('endpoint')}")
    test_result("limit is 5", data.get('limit') == 5, f"Got {data.get('limit')}")
    test_result("remaining is 5", data.get('remaining') == 5, f"Got {data.get('remaining')}")
    test_result("retry_after_seconds is 0", data.get('retry_after_seconds') == 0, f"Got {data.get('retry_after_seconds')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Fresh IP quota check", False, str(e))
    print(f"Error: {e}")

# Test 3.2: After 3 POSTs, remaining should be 2
print("\n3.2. After 3 POSTs, remaining should be 2")
print("-" * 80)
try:
    ip = "203.0.113.100"
    headers = {"x-forwarded-for": ip}
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "turnstile_token": "VALID.TOKEN"
    }
    
    # Send 3 POSTs
    for i in range(3):
        requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
        time.sleep(0.2)
    
    # Check quota
    response = requests.get(f"{API_BASE}/rate-limit/scan/github", headers=headers, timeout=10)
    data = response.json()
    
    test_result("After 3 POSTs, remaining is 2", data.get('remaining') == 2, f"Got {data.get('remaining')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("After 3 POSTs quota check", False, str(e))
    print(f"Error: {e}")

# Test 3.3: After 5 POSTs, remaining should be 0
print("\n3.3. After 5 POSTs total, remaining should be 0")
print("-" * 80)
try:
    ip = "203.0.113.100"
    headers = {"x-forwarded-for": ip}
    payload = {
        "repo_url": "https://github.com/vercel/next.js",
        "turnstile_token": "VALID.TOKEN"
    }
    
    # Send 2 more POSTs (total 5)
    for i in range(2):
        requests.post(f"{API_BASE}/scan/github", json=payload, headers=headers, timeout=10)
        time.sleep(0.2)
    
    # Check quota
    response = requests.get(f"{API_BASE}/rate-limit/scan/github", headers=headers, timeout=10)
    data = response.json()
    
    test_result("After 5 POSTs, remaining is 0", data.get('remaining') == 0, f"Got {data.get('remaining')}")
    test_result("retry_after_seconds > 0", data.get('retry_after_seconds', 0) > 0, f"Got {data.get('retry_after_seconds')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("After 5 POSTs quota check", False, str(e))
    print(f"Error: {e}")

# Test 3.4: Unknown endpoint returns 404
print("\n3.4. GET /api/rate-limit/does-not-exist")
print("-" * 80)
try:
    headers = {"x-forwarded-for": "203.0.113.101"}
    response = requests.get(f"{API_BASE}/rate-limit/does-not-exist", headers=headers, timeout=10)
    data = response.json()
    
    test_result("Unknown endpoint returns 404", response.status_code == 404, f"Got {response.status_code}")
    test_result("Response has ok: false", data.get('ok') == False, f"Got {data.get('ok')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Unknown endpoint 404", False, str(e))
    print(f"Error: {e}")

# ============================================================================
# 4) Static files (Priority 3)
# ============================================================================

print("\n" + "=" * 80)
print("4. Static files (Priority 3)")
print("=" * 80)

# Test 4.1: GET /.well-known/security.txt
print("\n4.1. GET /.well-known/security.txt")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/.well-known/security.txt", timeout=10)
    
    test_result("security.txt returns 200", response.status_code == 200, f"Got {response.status_code}")
    
    content_type = response.headers.get('Content-Type', '')
    test_result("Content-Type starts with 'text/plain'", content_type.startswith('text/plain'), f"Got {content_type}")
    
    body = response.text
    test_result("Body contains 'Contact:'", 'Contact:' in body, "Not found")
    test_result("Body contains 'Expires:'", 'Expires:' in body, "Not found")
    test_result("Body contains 'Canonical:'", 'Canonical:' in body, "Not found")
    test_result("Body contains 'Policy:'", 'Policy:' in body, "Not found")
    
    print(f"Content-Type: {content_type}")
    print(f"Body preview: {body[:200]}...")
except Exception as e:
    test_result("security.txt", False, str(e))
    print(f"Error: {e}")

# Test 4.2: GET /robots.txt
print("\n4.2. GET /robots.txt")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/robots.txt", timeout=10)
    
    test_result("robots.txt returns 200", response.status_code == 200, f"Got {response.status_code}")
    
    body = response.text
    test_result("Body contains 'Disallow: /api/'", 'Disallow: /api/' in body, "Not found")
    test_result("Body contains 'Disallow: /report/'", 'Disallow: /report/' in body, "Not found")
    test_result("Body contains 'Disallow: /downloads/'", 'Disallow: /downloads/' in body, "Not found")
    test_result("Body contains 'Sitemap:'", 'Sitemap:' in body, "Not found")
    
    print(f"Body:\n{body}")
except Exception as e:
    test_result("robots.txt", False, str(e))
    print(f"Error: {e}")

# Test 4.3: GET /sitemap.xml
print("\n4.3. GET /sitemap.xml")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/sitemap.xml", timeout=10)
    
    test_result("sitemap.xml returns 200", response.status_code == 200, f"Got {response.status_code}")
    
    content_type = response.headers.get('Content-Type', '')
    test_result("Content-Type contains 'xml'", 'xml' in content_type.lower(), f"Got {content_type}")
    
    body = response.text
    test_result("Body contains '<urlset'", '<urlset' in body, "Not found")
    
    # Check for both / and /scan in <loc> entries
    has_root = f'{BASE_URL}</loc>' in body or f'{BASE_URL}/</loc>' in body
    has_scan = f'{BASE_URL}/scan</loc>' in body
    
    test_result("Body contains <loc> for '/'", has_root, "Not found")
    test_result("Body contains <loc> for '/scan'", has_scan, "Not found")
    
    print(f"Content-Type: {content_type}")
    print(f"Body preview: {body[:500]}...")
except Exception as e:
    test_result("sitemap.xml", False, str(e))
    print(f"Error: {e}")

# ============================================================================
# 5) Regression: existing endpoints
# ============================================================================

print("\n" + "=" * 80)
print("5. Regression: existing endpoints")
print("=" * 80)

# Test 5.1: GET /api/health
print("\n5.1. GET /api/health")
print("-" * 80)
try:
    response = requests.get(f"{API_BASE}/health", timeout=10)
    data = response.json()
    
    test_result("Health returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Health has ok: true", data.get('ok') == True, f"Got {data.get('ok')}")
    test_result("Health has service: 'vibesafe-marketing'", data.get('service') == 'vibesafe-marketing', f"Got {data.get('service')}")
    test_result("Health has turnstile_enabled: true", data.get('turnstile_enabled') == True, f"Got {data.get('turnstile_enabled')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Health endpoint", False, str(e))
    print(f"Error: {e}")

# Test 5.2: GET /api/stats
print("\n5.2. GET /api/stats")
print("-" * 80)
try:
    response = requests.get(f"{API_BASE}/stats", timeout=10)
    data = response.json()
    
    test_result("Stats returns 200", response.status_code == 200, f"Got {response.status_code}")
    test_result("Stats has numeric repos_scanned", isinstance(data.get('repos_scanned'), (int, float)), f"Got {data.get('repos_scanned')}")
    test_result("Stats has numeric vulnerabilities_found", isinstance(data.get('vulnerabilities_found'), (int, float)), f"Got {data.get('vulnerabilities_found')}")
    test_result("Stats has numeric savings_usd", isinstance(data.get('savings_usd'), (int, float)), f"Got {data.get('savings_usd')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Stats endpoint", False, str(e))
    print(f"Error: {e}")

# Test 5.3: GET /api/scan/does-not-exist
print("\n5.3. GET /api/scan/does-not-exist")
print("-" * 80)
try:
    response = requests.get(f"{API_BASE}/scan/does-not-exist", timeout=10)
    data = response.json()
    
    test_result("Invalid scan_id returns 404", response.status_code == 404, f"Got {response.status_code}")
    test_result("Response has ok: false", data.get('ok') == False, f"Got {data.get('ok')}")
    
    print(f"Response: {json.dumps(data, indent=2)}")
except Exception as e:
    test_result("Invalid scan_id 404", False, str(e))
    print(f"Error: {e}")

# ============================================================================
# Summary
# ============================================================================

print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)
print(f"Total tests: {passed + failed}")
print(f"✅ Passed: {passed}")
print(f"❌ Failed: {failed}")
print(f"Success rate: {(passed / (passed + failed) * 100):.1f}%")

if failed > 0:
    print("\nFailed tests:")
    for name, success, message in test_results:
        if not success:
            print(f"  ❌ {name}: {message}")

print("\n" + "=" * 80)

# Exit with appropriate code
exit(0 if failed == 0 else 1)
