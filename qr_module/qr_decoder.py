import cv2
from pyzbar.pyzbar import decode

def decode_qr_from_image(image_path):
    """
    Input: path to QR code image
    Output: decoded URL string or None
    """
    img = cv2.imread(image_path)
    decoded_objects = decode(img)

    if decoded_objects:
        url = decoded_objects[0].data.decode('utf-8')
        return url
    else:
        return None