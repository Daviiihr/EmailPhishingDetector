from scanner import analyze_email

if __name__ == "__main__":
    test_subject ="=?utf-8?q?Acci=C3=B3n_Requerida=3A_Cuenta_Bloqueada?="

    body_test = """
        <html>
          <body>
            <p>Estimado usuario, se requiere acci&#243;n <b>urgente</b>.</p>
            <p>Su c\u200buen\u200bta ha sido suspendida.</p>
            <div style="display:none">Este texto es ignorado por el usuario pero confunde a los filtros</div>
            <p>Verifique su identidad aqu&#x2F;:
               <a href="http://xn--googl-0qa.com/login">https://www.google.com/login</a>
            </p>
          </body>
        </html>
        """
    result = analyze_email(test_subject, body_test)

    print("=== Analysis Report ===")
    print(f"Score: {result['Risky score']}")
    print(f"Veredict: {'PHISHING DETECTED' if result['Is phishing'] else 'Clean Email'}")
    print("Warning    :")
    for warning in result['Warning']:
        print(f" [!] {warning}")
