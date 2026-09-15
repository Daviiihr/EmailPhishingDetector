from config import pattern, IP_URL_PATTERN, SUSPICIOUS_DOMAIN, SHORTS
from decoder import decode_text, analyze_html

def analyze_email(affair, raw_boddy):
    score = 0
    warning = []

    clean_affair = decode_text(affair)
    decode_boddy = decode_text(raw_boddy)
    html_data = analyze_html(decode_boddy)

    total_text = f"{clean_affair}{html_data['Clean text']}"

    urgency = pattern.findall(total_text)
    if urgency:
        score += len(set(urgency)) * 2
        warning.append(f"Urgency detected: {set(urgency)}")

    if html_data['There is hidden text']:
        score += 4
        warning.append("Urgency detected: HTML elements hidden with CSS")

    for link in html_data['Links']:
        url = link['real URL']
        anchor = link['Anchor Text']

        if IP_URL_PATTERN.match(url):
            score += 5
            warning.append(f"IP-based URL: {url}")

        if any(s in url for s in SHORTS):
            score += 3
            warning.append(f"URL Shortener : {url}")

        if any(d in url for d in SUSPICIOUS_DOMAIN):
            score += 4
            warning.append(f"Risky domain extension: {url}")

        if "." in anchor and not " " in anchor and anchor.lower() not in url.lower():
            if "http" in anchor or "www" in anchor or ".com" in anchor:
                warning.append(f"Visual Spoofing: The text {anchor} redirects to {url}")

    return {
        "Risky score": score,
        "Is phishing": score >=5,
        "Warning": warning
    }
