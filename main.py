# Funcion de analisis

def analyze_phishing(affair, body):
    full_text = f"{affair} {body}"
    risk_score = 0
    warning = []

    pattern_search = pattern.findall(full_text)
    if pattern_search:
        risk_score += len(set(pattern_search)) * 2
        warning.append(f"Keywords found: {set(pattern_search)}")

    urls = url_pattern.findall(full_text)
    for url in urls:
        if IP_URL_PATTERN.match(url):
            risk_score += 5
            warning.append(f"IP URL found: {url}")

        if any(shorts in url for shorts in SHORTS):
            risk_score += 3
            warning.append(f"Short URL found: {url}")

        if any(domain in url for domain in SUSPICIOUS_DOMAIN):
            risk_score += 4
            warning.append(f"Suspicious domain found: {url}")

    resultado = {
        "Risk Score": risk_score,
        "Warning": warning,
        "Is phishing": risk_score >=5
    }
    return resultado
