import re

# Definicion de patrones irregulares para buscar elementos claves del phishing

pattern = re.compile(
    r'\b(urgente|inmediato|cuenta suspendida|verificar|actualizar datos|alerta de seguridad|bloqueada)\b',
    re.IGNORECASE,
)

url_pattern = re.compile(
    r'https?://[^\s<>"]+|www\.[^\s<>"]+'
)

IP_URL_PATTERN = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
SUSPICIOUS_DOMAIN = ['.xyz', '.top', '.gq', '.ml', '.cf', '.tk', '.cc', '.buzz']
SHORTS = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly']
