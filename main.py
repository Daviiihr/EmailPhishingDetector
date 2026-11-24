"""Entry point for running a quick demonstration of the Email Phishing Detector."""

from phishing_detector import analyze_email


def run_demo() -> None:
    test_subject = "=?utf-8?q?Acci=C3=B3n_Requerida=3A_Cuenta_Bloqueada?="
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
    report = analyze_email(
        test_subject,
        body_test,
        sender="Soporte Google <alertas@seguridad-cuenta.xyz>",
    )

    print("=== Email Phishing Analysis Report ===")
    print(f"Trace ID:    {report.trace_id}")
    print(f"Subject:     {report.subject}")
    print(f"Risk Score:  {report.risk_score} ({report.risk_level.value})")
    print(f"Verdict:     {report.verdict.value}")
    print(f"Action:      {report.recommended_action.value}")
    print("Findings:")
    for finding in report.findings:
        print(f"  [+{finding.score} | {finding.stage}] {finding.title}: {finding.description}")


if __name__ == "__main__":
    run_demo()
