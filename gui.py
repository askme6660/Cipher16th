import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QFormLayout, QLabel, QPushButton, QTextEdit, QComboBox
from PyQt5.QtCore import pyqtSlot
from cipher import CustomCipher16

class CustomCipher16App(QWidget):
    def __init__(self):
        super().__init__()
        self.title = 'Cipher16th'
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle(self.title)
        
        layout = QVBoxLayout()
        
        formLayout = QFormLayout()
        
        self.keyLabel = QLabel('Key:')
        self.keyDisplay = QLabel('0f1e2d3c4b5a69788796a5b4c3d2e1f0')
        formLayout.addRow(self.keyLabel, self.keyDisplay)
        
        self.modeLabel = QLabel('Mode:')
        self.modeInput = QComboBox()
        self.modeInput.addItems(['ECB', 'CBC', 'CFB', 'OFB', 'CTR'])
        formLayout.addRow(self.modeLabel, self.modeInput)
        
        self.plainTextLabel = QLabel('Plain Text:')
        self.plainTextInput = QTextEdit()
        formLayout.addRow(self.plainTextLabel, self.plainTextInput)
        
        self.cipherTextLabel = QLabel('Cipher Text:')
        self.cipherTextInput = QTextEdit()
        self.cipherTextInput.setReadOnly(True)
        formLayout.addRow(self.cipherTextLabel, self.cipherTextInput)
        
        self.decryptTextLabel = QLabel('Decrypted Text:')
        self.decryptTextInput = QTextEdit()
        self.decryptTextInput.setReadOnly(True)
        formLayout.addRow(self.decryptTextLabel, self.decryptTextInput)
        
        layout.addLayout(formLayout)
        
        self.encryptButton = QPushButton('Encrypt')
        self.encryptButton.clicked.connect(self.encrypt)
        layout.addWidget(self.encryptButton)
        
        self.decryptButton = QPushButton('Decrypt')
        self.decryptButton.clicked.connect(self.decrypt)
        layout.addWidget(self.decryptButton)
        
        self.setLayout(layout)
    
    @pyqtSlot()
    def encrypt(self):
        key = self.keyDisplay.text()
        mode = self.modeInput.currentText()
        plaintext = self.plainTextInput.toPlainText()
        
        cipher = CustomCipher16(key)
        try:
            ciphertext = cipher.encrypt(plaintext, mode)
            self.cipherTextInput.setPlainText(ciphertext)
        except Exception as e:
            self.cipherTextInput.setPlainText(f"Error: {str(e)}")
    
    @pyqtSlot()
    def decrypt(self):
        key = self.keyDisplay.text()
        mode = self.modeInput.currentText()
        ciphertext = self.cipherTextInput.toPlainText()
        
        cipher = CustomCipher16(key)
        try:
            decrypted_text = cipher.decrypt(ciphertext, mode)
            self.decryptTextInput.setPlainText(decrypted_text)
        except Exception as e:
            self.decryptTextInput.setPlainText(f"Error: {str(e)}")
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = CustomCipher16App()
    ex.show()
    sys.exit(app.exec_())
