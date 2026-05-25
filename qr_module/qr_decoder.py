import cv2

def decode_qr(image_path):

    image = cv2.imread(image_path)

    detector = cv2.QRCodeDetector()

    data, bbox, straight_qrcode = detector.detectAndDecode(image)

    if data:
        return data

    return None