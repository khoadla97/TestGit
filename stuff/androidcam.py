import requests
import cv2
import numpy as np 

url = 'http://192.168.9.100:8080/shot.jpg'
def main():
	while (True):
		img_resp = requests.get(url)
		img_arr = np.array(bytearray(img_resp.content), dtype=np.uint8)
		img = cv2.imdecode(img_arr, -1)
		img_rs = cv2.resize(img, (1280,720))
		cv2.imshow("AndroidCam", img_rs)

		if cv2.waitKey(1) == 27:
			break
if __name__ == '__main__':
    main()
