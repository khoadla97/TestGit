#Giao dien 
#Thuc hien: DANG LE ANH KHOA - NGUYEN KHAC TRUNG TIN

#import thu vien xu ly
import sys
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.uic import loadUi
import cv2
import requests
import numpy as np 
import time 
import threading

#Khoi tao class Worker de chuong trinh nhan dang chay dong bo voi GUI
class Worker(QRunnable):  
    @pyqtSlot()
    def run(self):
        print("thread start")
        import multiprocess_detect_actions 
        multiprocess_detect_actions.main() 
        print("Thread complete")

#Khoi tao class GUI
class NhandangGUI(QDialog,):
    def __init__(self):
        super(NhandangGUI, self).__init__()
        loadUi('NhandangGUI.ui', self)
        print('load NhandangGUI')
        self.urlEdit.setText('192.168.9.100:8080')          #set dia chi ip ban dau  
        self.turnon.clicked.connect(self.Start)             #connect vao Star
        self.screenshot.clicked.connect(self.Screenshot)    #connect Screenshot
        self.turnoff.clicked.connect(self.Shutdown)         #connect Shutdown
        self.runmain.clicked.connect(self.Rundetect)
        self.threadpool = QThreadPool()

    #Khoi tao button Bat dau chuong trinh
    def Start(self, img, window = 1):
        print('bat camera')
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_frames)
        self.timer.start(20)

    #Lay frame tu camera cua dien thoai
    def update_frames(self):
        url = self.urlEdit.text()
        url = 'http://'+url+'/shot.jpg'
        img_resp = requests.get(url)
        img_arr = np.array(bytearray(img_resp.content), dtype=np.uint8)
        img = cv2.imdecode(img_arr, -1)
        img_rs = cv2.resize(img, (1280,720))
        self.displayImage(img_rs, 1)

    #Hien thi hinh anh len GUI
    def displayImage(self, img, window = 1):
        qformat = QImage.Format_RGB888
        outImage = QImage(img, img.shape[1], img.shape[0], img.strides[0], qformat)
        outImage = outImage.rgbSwapped()
        if window == 1:
            self.showcam.setPixmap(QPixmap.fromImage(outImage))
            self.showcam.setScaledContents(True)
    
    #Chay chuong trinh chinh
    def Rundetect(self):
    	print('chay chuong trinh nhan dang')
    	worker = Worker()
    	self.threadpool.start(worker)
    
    #Tao button tat chuong trinh        
    def Shutdown(self):
        print("tat chuong trinh")
        sys.exit()
    
    #Tao button chup man hinh    
    def Screenshot(self):
        url = self.urlEdit.text()
        url = 'http://'+url+'/shot.jpg'
        img_resp_2 = requests.get(url)
        img_arr_2 = np.array(bytearray(img_resp_2.content), dtype=np.uint8)
        img_2 = cv2.imdecode(img_arr_2, -1)
        cv2.imwrite("screenshot.jpg", img_2)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NhandangGUI()
    window.setWindowTitle('Nhan dang')
    window.show()
    sys.exit(app.exec_())

