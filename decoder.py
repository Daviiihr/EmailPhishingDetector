import html
import quopri
import base64
import unicodedata
import idna
from bs4 import BeautifulSoup
import ftfy

def decode_text(raw_text):
    if not raw_text:
        return ""

    text = ftfy.fix_text(raw_text)

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
