from qr_decoder import decode_qr_from_image

# Put any sample QR image in qr_module/ folder to test
result = decode_qr_from_image("sample_qr.png")
print("Decoded URL:", result)