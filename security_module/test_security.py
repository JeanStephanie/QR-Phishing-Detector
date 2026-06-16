from qr_module.qr_decoder import decode_qr_from_image
from security_module.url_analyzer import analyze_url

# Extract URL from QR image
url = decode_qr_from_image("sample_qr.png")

if url:
    print("URL Extracted:", url)

    result = analyze_url(url)

    print("\nSecurity Analysis")
    print("Risk Score:", result["risk_score"])
    print("Status:", result["status"])

    print("\nReasons:")
    for reason in result["reasons"]:
        print("-", reason)

else:
    print("No QR code detected")