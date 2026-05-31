import cv2
from pyzbar.pyzbar import decode

def scan_qr_from_webcam():
    cap = cv2.VideoCapture(0)
    print("Press Q to quit")

    while True:
        ret, frame = cap.read()
        decoded_objects = decode(frame)

        for obj in decoded_objects:
            url = obj.data.decode('utf-8')
            print("QR Detected:", url)
            cap.release()
            cv2.destroyAllWindows()
            return url

        cv2.imshow("QR Scanner", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    return None

# This actually CALLS the function when you run the file
scan_qr_from_webcam()