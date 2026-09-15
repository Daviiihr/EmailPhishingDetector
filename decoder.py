import html
import quopri
import base64
import unicodedata
import idna
from bs4 import BeautifulSoup
import ftfy
from email.header import decode_header

def decode_text(raw_text):
    if not raw_text:
        return ""

    # Decodificar cabeceras RFC 2047 MIME (ej: =?utf-8?q?...?=)
    try:
        decoded_parts = decode_header(raw_text)
        text_parts = []
        for bytes_or_str, encoding in decoded_parts:
            if isinstance(bytes_or_str, bytes):
                text_parts.append(bytes_or_str.decode(encoding or 'utf-8', errors='ignore'))
            else:
                text_parts.append(str(bytes_or_str))
        text = "".join(text_parts)
    except Exception:
        text = raw_text

    text = ftfy.fix_text(text)

    if "=" in text:
            try:
                text = quopri.decodestring(text.encode('utf-8')).decode('utf-8', errors='ignore')
            except Exception:
                pass

    try:
        if len(text) > 20 and " " not in text.strip() and len(text.strip()) % 4 == 0:
            b64_decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if any(c.isalpha() for c in b64_decoded):
                text = b64_decoded
    except Exception:
        pass

    text = html.unescape(text)

    invisibles = ['\u200b','\u200c','\u200d','\uFEFF', '\u00ad' ]
    for char in invisibles:
        text = text.replace(char, "")

    text = unicodedata.normalize('NFKC', text)
    return text

def analyze_html(body_html):
    soup = BeautifulSoup(body_html, 'html.parser')

    links = []
    visible_texts = []
    hidden_texts = []

    for a in soup.find_all('a', href=True):
        original_url = a['href']
        anchor_text = a.get_text(strip=True)

        processed_url = original_url

        if 'xn--' in original_url:
            try:
                parts = original_url.split('/')
                if len(parts) > 2:
                    domain = parts[2]
                    clean_domain = idna.decode(domain)
                    processed_url = original_url.replace(domain, clean_domain)
            except Exception:
                pass

        links.append({
            "real URL": processed_url,
            "Anchor Text": anchor_text
        })

    for element in soup.find_all(True):
        if element.name in ['style', 'script', 'head', 'title', 'meta']:
            continue

        style = element.get('style', '').lower()
        element_text = element.get_text(strip=True)

        if element_text:
            if 'display:none' in style or 'visibility:hidden' in style or 'opacity:0' in style:
                hidden_texts.append(element_text)
            else:
                if element.find(string=True, recursive=False):
                    visible_texts.append(element.find(string=True, recursive=False).strip())

    return {
        "Links": links,
        "Clean Text": " ".join(visible_texts),
        "There is hidden text": len(hidden_texts) > 0
    }
