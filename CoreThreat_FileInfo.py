import sys
import hashlib
import os
import requests
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QPushButton, QMessageBox

# VirusTotal API-Key
api_key = 'YOUR VIRUSTOTAL API KEY'

class DragDropWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.headline = QLabel("Core|Threat Fileinfo", self)

        # Create labels to display the file path, MD5 sum, filetype, and filesize
        self.path_label = QLabel("File Path: ", self)
        self.md5_label = QLabel("MD5: ", self)
        self.filetype_label = QLabel("File Type: ", self)
        self.filesize_label = QLabel("File Size: ", self)
        self.vt_result_label = QLabel("VirusTotal Result: ", self)  # New label for VirusTotal result

        font = QFont("Arial", 16)
        self.headline.setFont(font)
        self.headline.setStyleSheet("color: white; font-weight: bold;")

        # Create a layout to arrange the labels vertically
        layout = QVBoxLayout(self)
        layout.addWidget(self.headline)
        layout.addWidget(self.path_label)
        layout.addWidget(self.md5_label)
        layout.addWidget(self.filetype_label)
        layout.addWidget(self.filesize_label)
        layout.addWidget(self.vt_result_label)

        # Create a button to trigger the VirusTotal API check
        self.check_vt_button = QPushButton("Check hash with VirusTotal", self)
        self.check_vt_button.clicked.connect(self.check_with_virustotal)

        # Add the button to the layout
        layout.addWidget(self.check_vt_button)

        # Set the layout to the widget
        self.setLayout(layout)

        # Set properties for labels
        for label in [self.path_label, self.md5_label, self.filetype_label, self.filesize_label, self.vt_result_label]:
            label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)  # Enable text selection by mouse

        # Set the widget to accept drops
        self.setAcceptDrops(True)


    def calculate_md5(self, file_path):
        # Calculate the MD5 hash of the file content
        md5 = hashlib.md5()
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                md5.update(chunk)
        return md5.hexdigest()

    def get_file_type(self, file_path):
        # Get the file type based on the file extension
        _, file_extension = os.path.splitext(file_path)
        return file_extension.upper()

    def get_file_size(self, file_path):
        # Get the file size in a human-readable format
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0

    def dragEnterEvent(self, event):
        # Check if the dragged data is a file
        if event.mimeData().hasUrls():
            # Accept the drop if the file is a valid type
            event.accept()
        else:
            # Reject the drop if the file is not a valid type
            event.ignore()

    def dropEvent(self, event):
        # Get the file path from the dropped data
        file_path = event.mimeData().urls()[0].toLocalFile()

        # Calculate the MD5 hash of the file content
        md5_hash = self.calculate_md5(file_path)

        # Get the file type
        file_type = self.get_file_type(file_path)

        # Get the file size
        file_size = self.get_file_size(file_path)

        # Update the labels to display the file information
        self.path_label.setText(f"File Path: {file_path}")
        self.md5_label.setText(f"MD5: {md5_hash}")
        self.filetype_label.setText(f"File Type: {file_type}")
        self.filesize_label.setText(f"File Size: {file_size}")

        # Clear the previous VirusTotal result when a new file is dropped
        self.vt_result_label.setText("VirusTotal Result: ")

    def check_with_virustotal(self):
        # Get the MD5 hash from the label
        md5_hash = self.md5_label.text().split(":")[1].strip()

        if md5_hash:        

            # Make a request to the VirusTotal API
            url = f'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': api_key, 'resource': md5_hash}
            response = requests.get(url, params=params)

            # Check the response
            if response.status_code == 200:
                result = response.json()
                if result['response_code'] == 1:
                    positives = result['positives']
                    total = result['total']
                    vt_result = f"VirusTotal Scan Result: {positives}/{total} detected."
                else:
                    vt_result = "VirusTotal Scan Result: Not available."
            else:
                vt_result = "Error connecting to VirusTotal API."

            # Display the VirusTotal result in the label
            self.vt_result_label.setText(vt_result)
        else:
            # Handle the case where the MD5 hash is empty
            QMessageBox.warning(self, "Warning", "Please drop a file first to calculate the MD5 hash.")


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Set the application name (title)
    app.setApplicationName("CoreThreat - FileInfo")

    widget = DragDropWidget()
    widget.resize(600, 200)  # Set the initial size of the widget
    widget.show()
    sys.exit(app.exec_())
