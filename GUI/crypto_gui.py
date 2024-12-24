import sys, os, time
from PyQt5.QtCore import Qt
from functools import partial
from PyQt5.QtWidgets import (QApplication, QScrollArea, QFormLayout, QWidget, QLabel, 
                             QRadioButton, QVBoxLayout, QTabWidget, QLineEdit, QPushButton, 
                             QFileDialog, QComboBox, QGridLayout, QMessageBox, QTextEdit)


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
import interface

class mainWindow(QWidget):

    def __init__(self, parent=None):
        super(mainWindow, self).__init__(parent)
        self.initUI()
        
    def initUI(self):
        # Main layout
        self.layout = QVBoxLayout(self)
        self.setFixedSize(657, 650)
        self.setWindowTitle('Crypto Tool')

        # Tabs
        self.tabs = QTabWidget()
        self.tab1 = QWidget()  
        self.tab2 = QWidget()  
        self.tab3 = QWidget()
        self.tab4 = QWidget()  # Info tab

        self.tabs.addTab(self.tab1, "            Keys & Signature                               ")
        self.tabs.addTab(self.tab2, "            Encrypt/Decrypt & Hashing                      ")
        self.tabs.addTab(self.tab3, "            CRC & CMAC & random                            ")
        self.tabs.addTab(self.tab4, "            About Crypto Tool                              ")

        self.layout.addWidget(self.tabs)

        # Setting up Tabs
        self.setupTabOne()
        self.setupTabTwo()
        self.setupTabThree()
        self.setupTabFour()
        self.apply_styles()

    def setupTabOne(self):
        # Mode Selector
        self.t1_mode_label = QLabel("Mode:")
        self.t1_mode_dropdown = QComboBox()
        self.t1_mode_dropdown.addItems([
            "Key Generation",
            "Key Conversion",
            "Generate Sign",
            "Verify Sign",
            "Generate Sign for Long Message",
            "Verify Sign for Long Message"
        ])
        self.t1_mode_dropdown.currentTextChanged.connect(lambda: self.t1_update_mode(self.t1_mode_dropdown.currentText()))
        self.t1_mode_dropdown.currentTextChanged.connect(lambda: self.t1_update_algorithm_options())
        self.t1_call_count = 0

        # Key Type Selection
        self.t1_key_type_label = QLabel("Key Type:")
        self.t1_key_type_dropdown = QComboBox()
        self.t1_key_type_dropdown.addItems(["RSA", "ECDSA", "ED25519", "Symmetric key"])
        self.t1_key_type_dropdown.setCurrentText("RSA")
        self.t1_key_type_dropdown.currentTextChanged.connect(lambda: self.t1_update_mode(self.t1_mode_dropdown.currentText()))
        self.t1_key_type_dropdown.currentTextChanged.connect(lambda: self.t1_update_algorithm_options())

        # key conversion
        self.t1_key_conversion_mode_label = QLabel("Conversion mode:")
        self.t1_pem_to_hex_radio = QRadioButton("PEM to HEX")
        self.t1_hex_to_pem_radio = QRadioButton("HEX to PEM")  
        self.t1_pem_to_hex_radio.toggled.connect(lambda : self.t1_update_mode(self.t1_mode_dropdown.currentText()))
        self.t1_hex_to_pem_radio.toggled.connect(lambda : self.t1_update_mode(self.t1_mode_dropdown.currentText()))
        
        # Algorithm Dropdown
        self.t1_algorithm_label = QLabel("Hash function:")
        self.t1_algorithm_dropdown = QComboBox()
        self.t1_update_algorithm_options()  # Default for RSA
        
        # Key Generation section
        self.t1_Key_size_label = QLabel("Key size:")
        self.t1_key_size_dropdown = QComboBox()
        self.t1_key_size_dropdown.addItems(["128", "256", "512", "1024"])

        self.t1_generate_key_btn = QPushButton("Generate Key")
        self.t1_generate_key_btn.clicked.connect(self.t1_generate_key)

        # Key conversion section
        self.t1_key_type_label = QLabel("key type:")

        self.t1_pem_to_hex_label = QLabel("PEM to HEX conversion")
        self.t1_hex_to_pem_label = QLabel("HEX to PEM conversion")

        self.t1_pem_key_file_btn = QPushButton("Load PEM Key")
        self.t1_pem_key_file_btn.clicked.connect(self.t1_load_pem_key)
        self.t1_pem_key_file_path_display = QLineEdit()
        self.t1_pem_key_file_path_display.setReadOnly(True)

        self.t1_hex_key_file_btn = QPushButton("Load HEX Key")
        self.t1_hex_key_file_btn.clicked.connect(self.t1_load_hex_key)
        self.t1_hex_key_file_path_display = QLineEdit()
        self.t1_hex_key_file_path_display.setReadOnly(True)

        self.t1_key_conversion_btn = QPushButton("Convert")
        self.t1_key_conversion_btn.clicked.connect(self.t1_convert_key)

        # Key file section
        self.t1_key_file_label = QLabel("Load Key")
        self.t1_private_key_file_btn = QPushButton("Load Private Key")
        self.t1_private_key_file_btn.clicked.connect(partial(self.load_private_key, "tab1"))
        self.t1_private_key_file_path_display = QLineEdit()
        self.t1_private_key_file_path_display.setReadOnly(True)

        self.t1_public_key_file_btn = QPushButton("Load Public Key")
        self.t1_public_key_file_btn.clicked.connect(partial(self.load_public_key, "tab1"))
        self.t1_public_key_file_path_display = QLineEdit()
        self.t1_public_key_file_path_display.setReadOnly(True)

        # Input file section
        self.t1_input_file_label = QLabel("Input File:")

        self.t1_input_file_btn = QPushButton("Load Input File")
        self.t1_input_file_btn.clicked.connect(partial(self.load_input_file, "tab1"))
        self.t1_input_file_path_display = QLineEdit()
        self.t1_input_file_path_display.setReadOnly(True)

        # Long Signature file section
        self.t1_hasher_file_label = QLabel("Hasher File:")
        self.t1_hasher_file_btn = QPushButton("Load Hasher File")
        self.t1_hasher_file_btn.clicked.connect(self.t1_load_hasher_file)
        self.t1_hasher_file_path = QLineEdit()
        self.t1_hasher_file_path.setReadOnly(True)

        self.t1_generate_hasher_btn = QPushButton("Generate Hasher")
        self.t1_generate_hasher_btn.clicked.connect(self.t1_generate_hasher)

        self.t1_update_hasher_btn = QPushButton("Update Hasher")
        self.t1_update_hasher_btn.clicked.connect(self.t1_update_hasher)

        # Signature file section
        self.t1_signature_file_label = QLabel("Signature File:")
        self.t1_signature_file_btn = QPushButton("Load Signature File")
        self.t1_signature_file_btn.clicked.connect(self.t1_load_signature_file)
        self.t1_signature_file_path_display = QLineEdit()
        self.t1_signature_file_path_display.setReadOnly(True)

        self.t1_generate_signature_btn = QPushButton("Generate Signature")
        self.t1_generate_signature_btn.clicked.connect(self.t1_generate_signature)

        self.t1_verify_signature_btn = QPushButton("Verify Signature")
        self.t1_verify_signature_btn.clicked.connect(self.t1_verify_signature)

        # Layout
        t1_layout = QGridLayout()
        t1_layout.setSpacing(10)

        # Add mode selector
        t1_layout.addWidget(self.t1_mode_label, 0, 0)
        t1_layout.addWidget(self.t1_mode_dropdown, 0, 1, 1, 3)

        # Key Type Selection
        t1_layout.addWidget(self.t1_key_type_label, 1, 0)
        t1_layout.addWidget(self.t1_key_type_dropdown, 1, 1, 1, 3)

        # Algorithm Dropdown
        t1_layout.addWidget(self.t1_algorithm_label, 2, 0)
        t1_layout.addWidget(self.t1_algorithm_dropdown, 2, 1, 1, 3)

        # Key conversion mode radio
        t1_layout.addWidget(self.t1_key_conversion_mode_label, 2, 0)
        t1_layout.addWidget(self.t1_pem_to_hex_radio, 2, 1)
        t1_layout.addWidget(self.t1_hex_to_pem_radio, 2, 2)
        
        # key size dropdown
        t1_layout.addWidget(self.t1_Key_size_label, 3, 0)
        t1_layout.addWidget(self.t1_key_size_dropdown, 3, 1, 1, 3)

        # Key conversion PEM to HEX
        t1_layout.addWidget(self.t1_pem_to_hex_label, 3, 0)
        t1_layout.addWidget(self.t1_pem_key_file_btn, 3, 1)
        t1_layout.addWidget(self.t1_pem_key_file_path_display, 3, 2, 1, 2)

        # Key conversion HEX to PEM
        t1_layout.addWidget(self.t1_hex_to_pem_label, 3, 0)
        t1_layout.addWidget(self.t1_hex_key_file_btn, 3, 1)
        t1_layout.addWidget(self.t1_hex_key_file_path_display, 3, 2, 1, 2)

        # convert button
        t1_layout.addWidget(self.t1_key_conversion_btn, 4, 0, 1, 4)

        # Keys
        t1_layout.addWidget(self.t1_generate_key_btn, 4, 0, 1, 4)
        t1_layout.addWidget(self.t1_key_file_label, 5, 0)
        t1_layout.addWidget(self.t1_private_key_file_btn, 5, 1)
        t1_layout.addWidget(self.t1_private_key_file_path_display, 5, 2, 1, 2)
        t1_layout.addWidget(self.t1_public_key_file_btn, 5, 1)
        t1_layout.addWidget(self.t1_public_key_file_path_display, 5, 2, 1, 2)

        # Input file
        t1_layout.addWidget(self.t1_input_file_label, 6, 0)
        t1_layout.addWidget(self.t1_input_file_btn, 6, 1)
        t1_layout.addWidget(self.t1_input_file_path_display, 6, 2, 1, 2)

        # Long message-related buttons
        t1_layout.addWidget(self.t1_hasher_file_label, 7, 0)
        t1_layout.addWidget(self.t1_hasher_file_btn, 7, 1)
        t1_layout.addWidget(self.t1_hasher_file_path, 7, 2, 1, 2)
        t1_layout.addWidget(self.t1_generate_hasher_btn, 8, 0, 1, 2)
        t1_layout.addWidget(self.t1_update_hasher_btn, 8, 2, 1, 2)

        # Signature File
        t1_layout.addWidget(self.t1_signature_file_label, 9, 0)
        t1_layout.addWidget(self.t1_signature_file_btn, 9, 1)
        t1_layout.addWidget(self.t1_signature_file_path_display, 9, 2, 1, 2)

        # Buttons for signature generation/verification
        t1_layout.addWidget(self.t1_generate_signature_btn, 10, 0, 1, 4)
        t1_layout.addWidget(self.t1_verify_signature_btn, 11, 0, 1, 4)

        # Add layout to tab
        self.tab1.setLayout(t1_layout)
        self.t1_update_mode("Key Generation")

    def setupTabTwo(self):
        # Mode selector
        self.t2_mode_label = QLabel("Mode:")
        self.t2_mode_dropdown = QComboBox()
        self.t2_mode_dropdown.addItems(["Encryption", "Decryption", "Generate Hash", "Verify Hash"])
        self.t2_mode_dropdown.currentTextChanged.connect(self.t2_update_mode)
        
        # Encryption Algorithm
        self.t2_encryption_mode_label = QLabel("Encryption Algorithm : ")
        self.t2_cbc_radio = QRadioButton("AES-CBC")
        self.t2_ctr_radio = QRadioButton("AES-CTR")
        self.t2_rsa_oaep_radio = QRadioButton("RSA-OAEP") 
        self.t2_cbc_radio.setChecked(True)
        self.t2_rsa_oaep_radio.toggled.connect(self.t2_update_mode)

        # Algorithm Dropdown for Hashing
        self.t2_algorithm_label = QLabel("Algorithm:")
        self.t2_algorithm_dropdown = QComboBox()
        self.t2_algorithm_dropdown.addItems(['SHA224','SHA256', 'SHA384', 'SHA512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'blake2b', 'blake2s', 'md5', 'SHA-1'])

        # Input File Section
        self.t2_input_file_label = QLabel("Input File:")
        self.t2_input_file_btn = QPushButton("Load Input File")
        self.t2_input_file_btn.clicked.connect(partial(self.load_input_file, "tab2"))
        self.t2_input_file_path_display = QLineEdit()
        self.t2_input_file_path_display.setReadOnly(True)

        # Initialization vector for encryption and decryption
        self.t2_iv_file_label = QLabel("Initialization vector : ")
        self.t2_iv_file_btn = QPushButton("Load IV file")
        self.t2_iv_file_btn.clicked.connect(self.t2_load_iv_file)
        self.t2_iv_file_path_display = QLineEdit()
        self.t2_iv_file_path_display.setReadOnly(True)

        # Key File Section
        self.t2_key_file_label = QLabel("Key File:")
        self.t2_key_file_btn = QPushButton("Load key")
        self.t2_key_file_btn.clicked.connect(partial(self.load_key_file, "tab2"))
        self.t2_key_file_path_display = QLineEdit()
        self.t2_key_file_path_display.setReadOnly(True)

        self.t2_private_key_file_btn = QPushButton("Load Private Key")
        self.t2_private_key_file_btn.clicked.connect(partial(self.load_private_key, "tab2"))
        self.t2_private_key_file_path_display = QLineEdit()
        self.t2_private_key_file_path_display.setReadOnly(True)

        self.t2_public_key_file_btn = QPushButton("Load Public Key")
        self.t2_public_key_file_btn.clicked.connect(partial(self.load_public_key, "tab2"))
        self.t2_public_key_file_path_display = QLineEdit()
        self.t2_public_key_file_path_display.setReadOnly(True)

        # Encrypted File Section
        self.t2_encrypted_file_label = QLabel("Encrypted File:")
        self.t2_encrypted_file_btn = QPushButton("Load Encrypted File")
        self.t2_encrypted_file_btn.clicked.connect(self.t2_load_encrypted_file)
        self.t2_encrypted_file_path_display = QLineEdit()
        self.t2_encrypted_file_path_display.setReadOnly(True)
        
        # Hash File Section
        self.t2_hash_file_label = QLabel("Hash File:")
        self.t2_hash_file_btn = QPushButton("Load Hash File")
        self.t2_hash_file_btn.clicked.connect(self.t2_load_hash_file)
        self.t2_hash_file_path_display = QLineEdit()
        self.t2_hash_file_path_display.setReadOnly(True)

        # Action Buttons
        self.t2_encrypt_btn = QPushButton("Encrypt")
        self.t2_encrypt_btn.clicked.connect(self.t2_encrypt)
        self.t2_decrypt_btn = QPushButton("Decrypt")
        self.t2_decrypt_btn.clicked.connect(self.t2_decrypt)
        self.t2_generate_hash_btn = QPushButton("Generate Hash")
        self.t2_generate_hash_btn.clicked.connect(self.t2_generate_hash)
        self.t2_verify_hash_btn = QPushButton("Verify Hash")
        self.t2_verify_hash_btn.clicked.connect(self.t2_verify_hash)

        # Layout Setup
        t2_layout = QGridLayout()
        t2_layout.setSpacing(10)

        t2_layout.addWidget(self.t2_mode_label, 0, 0)
        t2_layout.addWidget(self.t2_mode_dropdown, 0, 1, 1, 3)

        t2_layout.addWidget(self.t2_encryption_mode_label, 1, 0)
        t2_layout.addWidget(self.t2_cbc_radio, 1, 1)
        t2_layout.addWidget(self.t2_ctr_radio, 1, 2)
        t2_layout.addWidget(self.t2_rsa_oaep_radio, 1, 3)
        t2_layout.addWidget(self.t2_algorithm_label, 2, 0)
        t2_layout.addWidget(self.t2_algorithm_dropdown, 2, 1, 1, 3)

        t2_layout.addWidget(self.t2_input_file_label, 3, 0)
        t2_layout.addWidget(self.t2_input_file_btn, 3, 1)
        t2_layout.addWidget(self.t2_input_file_path_display, 3, 2, 1, 2)

        t2_layout.addWidget(self.t2_iv_file_label, 4, 0)
        t2_layout.addWidget(self.t2_iv_file_btn, 4, 1)
        t2_layout.addWidget(self.t2_iv_file_path_display, 4, 2, 1, 2)

        t2_layout.addWidget(self.t2_key_file_label, 5, 0)
        t2_layout.addWidget(self.t2_key_file_btn, 5, 1)
        t2_layout.addWidget(self.t2_key_file_path_display, 5, 2, 1, 2)
        t2_layout.addWidget(self.t2_private_key_file_btn, 5, 1)
        t2_layout.addWidget(self.t2_private_key_file_path_display, 5, 2, 1, 2)
        t2_layout.addWidget(self.t2_public_key_file_btn, 5, 1)
        t2_layout.addWidget(self.t2_public_key_file_path_display, 5, 2, 1, 2)
        
        t2_layout.addWidget(self.t2_encrypted_file_label, 6, 0)
        t2_layout.addWidget(self.t2_encrypted_file_btn, 6, 1)
        t2_layout.addWidget(self.t2_encrypted_file_path_display, 6, 2, 1, 2)

        t2_layout.addWidget(self.t2_hash_file_label, 6, 0)
        t2_layout.addWidget(self.t2_hash_file_btn, 6, 1)
        t2_layout.addWidget(self.t2_hash_file_path_display, 6, 2, 1, 2)

        t2_layout.addWidget(self.t2_encrypt_btn, 7, 0, 1, 4)
        t2_layout.addWidget(self.t2_decrypt_btn, 7, 0, 1, 4)
        t2_layout.addWidget(self.t2_generate_hash_btn, 8, 0, 1, 4)
        t2_layout.addWidget(self.t2_verify_hash_btn, 8, 0, 1, 4)

        self.tab2.setLayout(t2_layout)
        # Apply Styles
        self.apply_styles()

        # Call to set the initial visibility of components
        self.t2_update_mode()

    def setupTabThree(self):
        """Set up the advanced operations tab for CMAC, CRC Random Number Generation."""
        # Mode Selection
        self.t3_mode_label = QLabel("Operation Mode:")
        self.t3_mode_dropdown = QComboBox()
        self.t3_mode_dropdown.addItems([
            "Generate CMAC", "Verify CMAC", 
            "Generate CRC", "Verify CRC", 
            "Generate Random Numbers"
        ])
        self.t3_mode_dropdown.setCurrentText("Generate CMAC")
        self.t3_mode_dropdown.currentIndexChanged.connect(self.t3_update_mode)

        # CMAC mode selector
        self.t3_cmac_mode_label = QLabel("CMAC Mode: ")
        self.t3_with_time_stamp_radio = QRadioButton("With Time Stamp") 
        self.t3_without_time_stamp_radio = QRadioButton("Without Time Stamp")
        self.t3_without_time_stamp_radio.setChecked(True)
        self.t3_with_time_stamp_radio.toggled.connect(lambda : self.t3_update_mode())

        # Time stamp generation
        self.t3_time_stamp_label = QLabel("Time Stamp:")
        self.t3_time_stamp_btn = QPushButton("Generate time stamp")
        self.t3_time_stamp_btn.clicked.connect(self.t3_generate_time_stamp)
        self.t3_time_stamp_display = QLineEdit()
        self.t3_time_stamp_display.setReadOnly(True)

        self.t3_user_time_stamp_label = QLabel("Time stamp at generation:")
        self.t3_user_time_stamp_display = QLineEdit()
        self.t3_user_time_threshold_label = QLabel("Time Threshold:")
        self.t3_user_time_threshold_display = QLineEdit() 

        # Input File Section
        self.t3_input_file_label = QLabel("Input File:")
        self.t3_input_file_btn = QPushButton("Load Input File")
        self.t3_input_file_btn.clicked.connect(partial(self.load_input_file, "tab3"))
        self.t3_input_path_file_display = QLineEdit()
        self.t3_input_path_file_display.setReadOnly(True)

        # Key File Section
        self.t3_key_file_label = QLabel("Key File:")
        self.t3_key_file_btn = QPushButton("Load key file")
        self.t3_key_file_btn.clicked.connect(partial(self.load_key_file, "tab3"))
        self.t3_key_file_path_display = QLineEdit()
        self.t3_key_file_path_display.setReadOnly(True)

        # Algorithm dropdown for CRC
        self.t3_crc_algorithm_dropdown_label = QLabel("Algorithm :")
        self.t3_crc_algorithm_dropdown = QComboBox()
        self.t3_crc_algorithm_dropdown.addItems([
            "CRC-24", "CRC-32", "CRC-64", "xmodem", "modbus", "kermit", "x-25", "posix"
        ])

        # CMAC verification file
        self.t3_cmac_verification_file_label = QLabel("CMAC Verification File:")
        self.t3_cmac_verification_file_btn = QPushButton("Load CMAC File")
        self.t3_cmac_verification_file_btn.clicked.connect(partial(self.t3_load_verification_file, "CMAC"))
        self.t3_cmac_verification_path_display = QLineEdit()
        self.t3_cmac_verification_path_display.setReadOnly(True)


        # CRC verification File Section
        self.t3_crc_verification_file_label = QLabel("Verification File:")
        self.t3_crc_verification_file_btn = QPushButton("Load CRC File")
        self.t3_crc_verification_file_btn.clicked.connect(partial(self.t3_load_verification_file, "CRC"))
        self.t3_crc_verification_path_display = QLineEdit()
        self.t3_crc_verification_path_display.setReadOnly(True)

        # Action Buttons
        self.t3_generate_btn = QPushButton("Generate")
        self.t3_generate_btn.clicked.connect(self.t3_generate)
        self.t3_verify_btn = QPushButton("Verify")
        self.t3_verify_btn.clicked.connect(self.t3_verify)

        # Random Number Generation
        self.t3_number_of_bytes_label = QLabel("Number of Bytes:")
        self.t3_number_of_bytes_dropdown = QComboBox()
        self.t3_number_of_bytes_dropdown.addItems(["8", "16", "32", "64", "128", "256"])
        self.t3_random_number_btn = QPushButton("Generate Random Bytes")
        self.t3_random_number_btn.clicked.connect(self.generate_random_bytes)

        # Layout Setup
        t3_layout = QGridLayout()
        t3_layout.setSpacing(10)

        t3_layout.addWidget(self.t3_mode_label, 0, 0)
        t3_layout.addWidget(self.t3_mode_dropdown, 0, 1, 1, 3)

        t3_layout.addWidget(self.t3_cmac_mode_label, 1, 0, 1 , 1)
        t3_layout.addWidget(self.t3_without_time_stamp_radio, 1, 1)
        t3_layout.addWidget(self.t3_with_time_stamp_radio, 1, 2)

        t3_layout.addWidget(self.t3_time_stamp_label, 2, 0)
        t3_layout.addWidget(self.t3_time_stamp_btn, 2, 1)
        t3_layout.addWidget(self.t3_time_stamp_display, 2, 2, 1, 2)

        t3_layout.addWidget(self.t3_user_time_stamp_label, 2, 0)
        t3_layout.addWidget(self.t3_user_time_stamp_display, 2, 1, 1 , 3)
        t3_layout.addWidget(self.t3_user_time_threshold_label, 3, 0)
        t3_layout.addWidget(self.t3_user_time_threshold_display, 3, 1, 1 , 3)

        t3_layout.addWidget(self.t3_key_file_label, 4, 0)
        t3_layout.addWidget(self.t3_key_file_btn, 4, 1)
        t3_layout.addWidget(self.t3_key_file_path_display, 4, 2, 1, 2)

        t3_layout.addWidget(self.t3_crc_algorithm_dropdown_label, 4, 0)
        t3_layout.addWidget(self.t3_crc_algorithm_dropdown, 4, 1, 1, 3)

        t3_layout.addWidget(self.t3_number_of_bytes_label, 4, 0)
        t3_layout.addWidget(self.t3_number_of_bytes_dropdown, 4, 1, 1, 3)

        t3_layout.addWidget(self.t3_input_file_label, 5, 0)
        t3_layout.addWidget(self.t3_input_file_btn, 5, 1)
        t3_layout.addWidget(self.t3_input_path_file_display, 5, 2, 1, 2)

        t3_layout.addWidget(self.t3_cmac_verification_file_label, 6, 0)
        t3_layout.addWidget(self.t3_cmac_verification_file_btn, 6, 1)
        t3_layout.addWidget(self.t3_cmac_verification_path_display, 6, 2, 1, 2)

        t3_layout.addWidget(self.t3_crc_verification_file_label, 6, 0)
        t3_layout.addWidget(self.t3_crc_verification_file_btn, 6, 1)
        t3_layout.addWidget(self.t3_crc_verification_path_display, 6, 2, 1, 2)

        t3_layout.addWidget(self.t3_generate_btn, 7, 0, 1, 4)
        t3_layout.addWidget(self.t3_verify_btn, 7, 0, 1, 4)

        t3_layout.addWidget(self.t3_random_number_btn, 8, 0, 1, 4)


        self.tab3.setLayout(t3_layout)
        # Apply Styles
        self.apply_styles()

        # Update the mode to CMAC initially
        self.t3_update_mode()

    def setupTabFour(self):
        """Set up the readme tab with instructions on how to use the tool."""
        # Create a QTextEdit widget
        readme_text_edit = QTextEdit()
        readme_text_edit.setReadOnly(True)  # Make it read-only

        # Set the readme text
        readme_text = """
        <h1>Crypto Tool</h1>
        <p>Welcome to the Crypto Tool! This tool provides various cryptographic functionalities including key generation, encryption, decryption, hashing, and more.</p>
        
        <h2>Tab 1 : Keys & Signature</h2>

        <h3>Key Generation</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the key size for RSA/Symmetric keys or the hash function for ECDSA/ED25519 keys.</li>
                    <li>Click on the <b>Generate</b> button.</li>
                    <li>The generated key will be saved in the <code>temp/keys</code> directory.</li>
                </ul>
            </li>
        </ul>

        <h3>Generate Signature</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the key type and the hash function.</li>
                    <li>Load the corresponding key file and the input file that needs to be signed.</li>
                    <li>Click on the <b>Generate</b> button.</li>
                    <li>The signature file will be saved in the <code>temp/Sign</code> directory.</li>
                </ul>
            </li>
        </ul>

        <h3>Verify Signature</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the key type and the hash function.</li>
                    <li>Load the corresponding key file, the input file, and the signature file.</li>
                    <li>Click on the <b>Verify</b> button.</li>
                </ul>
            </li>
        </ul>

        <h3>Generate Signature for Long Messages</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>
                        <b>Generate a hasher:</b>
                        <ul>
                            <li>Select the hash function and click on the <b>Generate Hasher</b> button.</li>
                        </ul>
                    </li>
                    <li>
                        <b>Update the hasher with data:</b>
                        <ul>
                            <li>Load the input file and the previously generated hasher file.</li>
                            <li>Click on the <b>Update Hasher</b> button to add data from the input file to the hasher.</li>
                            <li>Repeat this step for each part of the long message until all data is updated in the hasher.</li>
                        </ul>
                    </li>
                    <li>
                        <b>Generate the signature:</b>
                        <ul>
                            <li>Select the key type and load the key file and the updated hasher file.</li>
                            <li>Click on the <b>Generate</b> button.</li>
                        </ul>
                    </li>
                    <li>The signature file will be saved in the <code>temp/Sign</code> directory.</li>
                </ul>
            </li>
        </ul>

        <h3>Verify Signature for Long Messages</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the key type and the hash function.</li>
                    <li>Load the corresponding key file, the updated hasher file, and the signature file.</li>
                    <li>Click on the <b>Verify</b> button.</li>
                </ul>
            </li>
        </ul>
        
        <h2>Encrypt/Decrypt & Hashing</h2>

        <h3>Encryption</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the encryption algorithm from the dropdown menu.</li>
                    <li>Load the input file that you want to encrypt.</li>
                    <li>Click on the <b>Encrypt</b> button to encrypt the file.</li>
                    <li>The encrypted file will be saved in the <code>temp/Encryption</code> directory.</li>
                </ul>
            </li>
        </ul>

        <h3>Decryption</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the decryption algorithm from the dropdown menu.</li>
                    <li>Load the encrypted file that you want to decrypt.</li>
                    <li>Click on the <b>Decrypt</b> button to decrypt the file.</li>
                </ul>
            </li>
        </ul>

        <h3>Generate Hash</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the hash algorithm from the dropdown menu (e.g., SHA-256, MD5, etc.).</li>
                    <li>Load the input file for which you want to generate a hash.</li>
                    <li>Click on the <b>Generate Hash</b> button to compute the hash value.</li>
                    <li>The hash value will be saved in the <code>temp/Hashes</code> directory as a file.</li>
                </ul>
            </li>
        </ul>

        <h3>Verify Hash</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the hash algorithm used to generate the hash (e.g., SHA-256, MD5, etc.).</li>
                    <li>Load the input file and the corresponding hash file for verification.</li>
                    <li>Click on the <b>Verify Hash</b> button.</li>
                    <li>The result will indicate whether the hash matches the input file (valid) or does not match (invalid).</li>
                </ul>
            </li>
        </ul>
        
        <h2>CRC, CMAC, & Random</h2>

        <h3>Generate CMAC</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the CMAC algorithm from the dropdown menu (e.g., AES-CMAC).</li>
                    <li>Load the input file for which you want to generate the CMAC.</li>
                    <li>Provide or load the CMAC key as required by the algorithm.</li>
                    <li>Click on the <b>Generate CMAC</b> button.</li>
                    <li>The generated CMAC will be displayed on the screen or saved in the <code>temp/CMAC</code> directory.</li>
                </ul>
            </li>
        </ul>

        <h3>Verify CMAC</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the CMAC algorithm used to generate the CMAC (e.g., AES-CMAC).</li>
                    <li>Load the input file, the CMAC value file, and the corresponding key.</li>
                    <li>Click on the <b>Verify CMAC</b> button.</li>
                    <li>The result will indicate whether the CMAC matches the input file (valid) or does not match (invalid).</li>
                </ul>
            </li>
        </ul>

        <h3>Generate CRC</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the CRC algorithm or polynomial from the dropdown menu (e.g., CRC-32, CRC-16).</li>
                    <li>Load the input file for which you want to generate the CRC.</li>
                    <li>Click on the <b>Generate CRC</b> button.</li>
                    <li>The generated CRC value will be displayed on the screen or saved in the <code>temp/CRC</code> directory.</li>
                </ul>
            </li>
        </ul>

        <h3>Verify CRC</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the CRC algorithm or polynomial used to generate the CRC (e.g., CRC-32, CRC-16).</li>
                    <li>Load the input file and the corresponding CRC value file.</li>
                    <li>Click on the <b>Verify CRC</b> button.</li>
                    <li>The result will indicate whether the CRC matches the input file (valid) or does not match (invalid).</li>
                </ul>
            </li>
        </ul>

        <h3>Generate Random Numbers</h3>
        <ul>
            <li>
                <b>Steps:</b>
                <ul>
                    <li>Select the type of random generation (e.g., numbers, bytes) from the dropdown menu.</li>
                    <li>Specify the desired length or range for the random output.</li>
                    <li>Click on the <b>Generate Random</b> button.</li>
                    <li>The generated random numbers or bytes will be displayed on the screen or saved in the <code>temp/Random</code> directory.</li>
                </ul>
            </li>
        </ul>
        
        <h2>How to Use</h2>
        <p>Select the appropriate tab for the operation you want to perform. Follow the instructions and provide the necessary input files and parameters. Click the corresponding button to execute the operation.</p>
        """

        readme_text_edit.setHtml(readme_text)

        # Create a layout for Tab 4
        layout = QVBoxLayout()
        layout.addWidget(readme_text_edit)

        # Set the layout for Tab 4
        self.tab4.setLayout(layout)

    def t1_update_mode(self, mode):
        """Update the visibility of components based on the selected mode."""
        # Determine mode states
        key_conversion_mode = "conversion" in mode.lower()
        key_generation_mode = "key" in mode.lower() and not key_conversion_mode
        generate_sign_mode = "generate" in mode.lower() and "long" not in mode.lower()
        generate_long_sign_mode = "generate" in mode.lower() and "long" in mode.lower()
        verify_sign_mode = "verify" in mode.lower() and "long" not in mode.lower()
        verify_long_sign_mode = "verify" in mode.lower() and "long" in mode.lower()
        rsa_key_selected = "RSA" in self.t1_key_type_dropdown.currentText()
        sign_with_ed25519 = "ED25519" in self.t1_key_type_dropdown.currentText() and generate_sign_mode

        # Combined modes
        generate_mode = generate_sign_mode or generate_long_sign_mode
        verify_mode = verify_sign_mode or verify_long_sign_mode

        # Update visibility for each component
        # Key generation components
        self.t1_generate_key_btn.setVisible(key_generation_mode)
        self.t1_Key_size_label.setVisible(key_generation_mode and rsa_key_selected)
        self.t1_key_size_dropdown.setVisible(key_generation_mode and rsa_key_selected)

        # Key conversion components
        self.t1_algorithm_label.setVisible(not key_conversion_mode)
        self.t1_algorithm_dropdown.setVisible(not key_conversion_mode)
        self.t1_key_conversion_mode_label.setVisible(key_conversion_mode)
        self.t1_pem_to_hex_radio.setVisible(key_conversion_mode)
        self.t1_hex_to_pem_radio.setVisible(key_conversion_mode)
        self.t1_pem_to_hex_label.setVisible(key_conversion_mode and self.t1_pem_to_hex_radio.isChecked())
        self.t1_pem_key_file_btn.setVisible(key_conversion_mode and self.t1_pem_to_hex_radio.isChecked())
        self.t1_pem_key_file_path_display.setVisible(key_conversion_mode and self.t1_pem_to_hex_radio.isChecked())
        self.t1_hex_to_pem_label.setVisible(key_conversion_mode and self.t1_hex_to_pem_radio.isChecked())
        self.t1_hex_key_file_btn.setVisible(key_conversion_mode and self.t1_hex_to_pem_radio.isChecked())
        self.t1_hex_key_file_path_display.setVisible(key_conversion_mode and self.t1_hex_to_pem_radio.isChecked())
        self.t1_key_conversion_btn.setVisible(key_conversion_mode)

        # Private key (generation or signature generation modes)
        self.t1_private_key_file_btn.setVisible(generate_mode)
        self.t1_private_key_file_path_display.setVisible(generate_mode)
        self.t1_generate_signature_btn.setVisible(generate_mode)
        self.t1_key_file_label.setVisible(generate_mode or verify_mode)
        self.t1_algorithm_label.setVisible(not sign_with_ed25519)
        self.t1_algorithm_dropdown.setVisible(not sign_with_ed25519)
        
        # Public key (verification modes)
        self.t1_public_key_file_btn.setVisible(verify_mode)
        self.t1_public_key_file_path_display.setVisible(verify_mode)

        # Signature file (verification modes)
        self.t1_signature_file_btn.setVisible(verify_mode)
        self.t1_signature_file_path_display.setVisible(verify_mode)

        # Signature generation and verification buttons
        self.t1_signature_file_label.setVisible(verify_mode)
        self.t1_verify_signature_btn.setVisible(verify_mode)

        # Input file (not used in key generation mode)
        self.t1_input_file_label.setVisible(not key_generation_mode and not verify_long_sign_mode and not key_conversion_mode)
        self.t1_input_file_btn.setVisible(not key_generation_mode and not verify_long_sign_mode and not key_conversion_mode)
        self.t1_input_file_path_display.setVisible(not key_generation_mode and not verify_long_sign_mode and not key_conversion_mode)

        # Hasher file and buttons (only for long message modes)
        self.t1_hasher_file_label.setVisible(verify_long_sign_mode or generate_long_sign_mode)
        self.t1_hasher_file_btn.setVisible(verify_long_sign_mode or generate_long_sign_mode)
        self.t1_hasher_file_path.setVisible(verify_long_sign_mode or generate_long_sign_mode)
        self.t1_generate_hasher_btn.setVisible(generate_long_sign_mode)
        self.t1_update_hasher_btn.setVisible(generate_long_sign_mode)

    def t2_update_mode(self):
        """Update the UI fields based on the selected mode."""
        mode = self.t2_mode_dropdown.currentText()
        is_encryption_mode = "Encrypt" in mode
        is_decryption_mode = "Decrypt" in mode
        is_hash_mode = "Hash" in mode
        is_rsa_oaep_mode = self.t2_rsa_oaep_radio.isChecked()

        # Toggle visibility based on mode
        self.t2_key_file_label.setVisible(is_encryption_mode or is_decryption_mode)
        self.t2_key_file_btn.setVisible((is_encryption_mode or is_decryption_mode) and not is_rsa_oaep_mode)
        self.t2_key_file_path_display.setVisible((is_encryption_mode or is_decryption_mode) and not is_rsa_oaep_mode)
        self.t2_private_key_file_btn.setVisible(is_rsa_oaep_mode and is_decryption_mode)
        self.t2_private_key_file_path_display.setVisible(is_rsa_oaep_mode and is_decryption_mode)
        self.t2_public_key_file_btn.setVisible(is_rsa_oaep_mode and is_encryption_mode)
        self.t2_public_key_file_path_display.setVisible(is_rsa_oaep_mode and is_encryption_mode)

        self.t2_encryption_mode_label.setVisible(is_encryption_mode or is_decryption_mode)
        self.t2_iv_file_label.setVisible((is_encryption_mode or is_decryption_mode) and not is_rsa_oaep_mode)
        self.t2_iv_file_btn.setVisible((is_encryption_mode or is_decryption_mode) and not is_rsa_oaep_mode)
        self.t2_iv_file_path_display.setVisible((is_encryption_mode or is_decryption_mode) and not is_rsa_oaep_mode)
        
        self.t2_encrypt_btn.setVisible(is_encryption_mode)
        self.t2_input_file_label.setVisible(not is_decryption_mode)
        self.t2_input_file_btn.setVisible(not is_decryption_mode)
        self.t2_input_file_path_display.setVisible(not is_decryption_mode)
        self.t2_decrypt_btn.setVisible(is_decryption_mode)
        self.t2_encrypted_file_label.setVisible(is_decryption_mode)
        self.t2_encrypted_file_btn.setVisible(is_decryption_mode)
        self.t2_encrypted_file_path_display.setVisible(is_decryption_mode)
        
        self.t2_cbc_radio.setVisible(not is_hash_mode)
        self.t2_ctr_radio.setVisible(not is_hash_mode)
        self.t2_algorithm_label.setVisible(is_hash_mode or is_rsa_oaep_mode)
        self.t2_algorithm_dropdown.setVisible(is_hash_mode or is_rsa_oaep_mode)
        self.t2_rsa_oaep_radio.setVisible(not is_hash_mode)
        self.t2_hash_file_label.setVisible(is_hash_mode and "verify" in mode.lower())
        self.t2_hash_file_btn.setVisible(is_hash_mode and "verify" in mode.lower())
        self.t2_hash_file_path_display.setVisible(is_hash_mode and "verify" in mode.lower())
        self.t2_generate_hash_btn.setVisible(is_hash_mode and "generate" in mode.lower())
        self.t2_verify_hash_btn.setVisible(is_hash_mode and "verify" in mode.lower())

    def t3_update_mode(self):
        """Update the UI fields based on the selected mode."""
        mode = self.t3_mode_dropdown.currentText()
        is_verification_mode = "verify" in mode.lower()
        is_random_mode = "random" in mode.lower()
        is_generate_mode = "generate" in mode.lower() and not is_random_mode
        is_cmac_mode = "cmac" in mode.lower()
        is_crc_mode = "crc" in mode.lower()
        time_stamp_mode = self.t3_with_time_stamp_radio.isChecked()

        # Toggle visibility based on mode
        self.t3_cmac_mode_label.setVisible(is_cmac_mode)
        self.t3_time_stamp_label.setVisible(is_cmac_mode)
        self.t3_with_time_stamp_radio.setVisible(is_cmac_mode)
        self.t3_without_time_stamp_radio.setVisible(is_cmac_mode)

        self.t3_time_stamp_label.setVisible(is_cmac_mode and time_stamp_mode and is_generate_mode)
        self.t3_time_stamp_btn.setVisible(is_cmac_mode and time_stamp_mode and is_generate_mode)
        self.t3_time_stamp_display.setVisible(is_cmac_mode and time_stamp_mode and is_generate_mode)

        self.t3_user_time_stamp_label.setVisible(is_cmac_mode and time_stamp_mode and is_verification_mode)
        self.t3_user_time_stamp_display.setVisible(is_cmac_mode and time_stamp_mode and is_verification_mode)
        self.t3_user_time_threshold_label.setVisible(is_cmac_mode and time_stamp_mode and is_verification_mode)
        self.t3_user_time_threshold_display.setVisible(is_cmac_mode and time_stamp_mode and is_verification_mode)

        self.t3_crc_algorithm_dropdown_label.setVisible(is_crc_mode)
        self.t3_crc_algorithm_dropdown.setVisible(is_crc_mode)

        self.t3_key_file_label.setVisible(is_cmac_mode)
        self.t3_key_file_btn.setVisible(is_cmac_mode)
        self.t3_key_file_path_display.setVisible(is_cmac_mode)

        self.t3_generate_btn.setVisible(is_generate_mode)
        self.t3_verify_btn.setVisible(is_verification_mode)

        self.t3_input_file_label.setVisible(not is_random_mode)
        self.t3_input_file_btn.setVisible(not is_random_mode)
        self.t3_input_path_file_display.setVisible(not is_random_mode)

        self.t3_cmac_verification_file_label.setVisible(is_verification_mode and is_cmac_mode)
        self.t3_cmac_verification_file_btn.setVisible(is_verification_mode and is_cmac_mode)
        self.t3_cmac_verification_path_display.setVisible(is_verification_mode and is_cmac_mode)
        self.t3_crc_verification_file_label.setVisible(is_verification_mode and is_crc_mode)
        self.t3_crc_verification_file_btn.setVisible(is_verification_mode and is_crc_mode)
        self.t3_crc_verification_path_display.setVisible(is_verification_mode and is_crc_mode)

        self.t3_number_of_bytes_label.setVisible(is_random_mode)
        self.t3_number_of_bytes_dropdown.setVisible(is_random_mode)
        self.t3_random_number_btn.setVisible(is_random_mode)


    def apply_styles(self):
        """Apply styles for a more polished UI."""
        self.setStyleSheet("""
            QTabWidget::pane {
                border-top: 2px solid #444;
                padding: 5px;
                background: #F5F5F5;
            }
            QTabWidget::tab-bar {
                alignment: center;
            }
            QTabBar::tab {
                background: #D3D3D3;
                border: 1px solid #444;
                padding: 8px 15px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                color: #333;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #00509E;
                color: white;
                font-weight: bold;
            }
            QLabel {
                font-weight: bold;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fff;
            }
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                background-color: #0078D7;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00509E;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fff;
            }
            QRadioButton {
                font-weight: normal;
            }
            QWidget#tab1 {
                background-color: #f0f0f0;
                padding: 15px;
                border-radius: 5px;
            }
        """)

    def load_private_key(self, tab):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Key File', '', 'Key Files (*.key *.pem);;All Files (*)')
        if file_path:
            if tab == "tab1":
                self.t1_private_key_file_path_display.setText(file_path)
            elif tab == "tab2":
                self.t2_private_key_file_path_display.setText(file_path)
            else:
                pass
       
    def load_public_key(self, tab):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Key File', '', 'Key Files (*.key *.pem);;All Files (*)')
        if file_path:
            if tab == "tab1":
                self.t1_public_key_file_path_display.setText(file_path)
            elif tab == "tab2":
                self.t2_public_key_file_path_display.setText(file_path)
            else:
                pass
 
    def load_input_file(self, tab):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Encrypted File', '', 'All Files (*)')
        if file_path:
            if tab == "tab1":
                self.t1_input_file_path_display.setText(file_path)
            elif tab == "tab2":
                self.t2_input_file_path_display.setText(file_path)
            elif tab == "tab3":
                self.t3_input_path_file_display.setText(file_path)

    def load_key_file(self, tab):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Key File', '', 'Key Files (*.key *.pem);;All Files (*)')
        if tab == "tab2":
            self.t2_key_file_path_display.setText(file_path)
        else:
            self.t3_key_file_path_display.setText(file_path)

    def t1_update_algorithm_options(self):
        """Update dropdown based on the mode and selected key type."""
        current_mode = self.t1_mode_dropdown.currentText()
        key_type = self.t1_key_type_dropdown.currentText()
        self.t1_algorithm_dropdown.clear()

        if "Key" in current_mode:
            if key_type == "RSA":
                self.t1_algorithm_dropdown.addItems(["RSA-OAEP", "RSA-PSS"])
            elif key_type == "ECDSA":
                self.t1_algorithm_dropdown.addItems(["SECP192R1","SECP256R1","SECP384R1","SECP521R1","SECP256K1"])
            elif key_type == "ED25519":
                self.t1_algorithm_dropdown.addItem("Fixed hash function : SHA512")
            elif key_type == "Symmetric key":
                self.t1_algorithm_dropdown.addItems(["AES-128", "AES-192", "AES-256"])
            else:
                pass
        else:
            self.t1_algorithm_dropdown.addItems(["SHA256", "SHA384", "SHA512"])

    def t1_load_pem_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Key File', '', 'Key Files (*.key *.pem);;All Files (*)')
        if file_path:
            self.t1_pem_key_file_path_display.setText(file_path)

    def t1_load_hex_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Key File', '', 'Key Files (*.key *.hex);;All Files (*)')
        if file_path:
            self.t1_hex_key_file_path_display.setText(file_path)

    def t1_load_hasher_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open hasher File', '', 'Hash Files (*.hash *.hsh *.txt *.dat *.bin);;All Files (*)')
        if file_path:
            self.t1_hasher_file_path.setText(file_path)

    def t1_load_signature_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Signature File', '', 'All Files (*)')
        if file_path:
            self.t1_signature_file_path_display.setText(file_path)

    def t1_generate_key(self):
        key_type = self.t1_key_type_dropdown.currentText()
        if key_type == "RSA":
            retList = interface.If_generateKey(key_type, self.t1_key_size_dropdown.currentText())
        else:
            retList = interface.If_generateKey(key_type, self.t1_algorithm_dropdown.currentText())
        if retList[0] == "Success":
            QMessageBox.information(self, "Key Generation", "Key generated successfully!")
        else:
            QMessageBox.information(self, "Key Generation", retList[1])

    def t1_convert_key(self):
        if self.t1_pem_to_hex_radio.isChecked():
            if not self.t1_pem_key_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a PEM key for conversion.")
            else:
                retList = interface.If_pem_to_hex(
                    self.t1_key_type_dropdown.currentText(),
                    self.t1_pem_key_file_path_display.text()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Key Conversion", "PEM to HEX conversion successful!")
                else:
                    QMessageBox.warning(self, "Key Conversion", retList[1])
        elif self.t1_hex_to_pem_radio.isChecked():
            if not self.t1_hex_key_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a hex key for conversion.")
            else:
                retList = interface.If_hex_to_pem(
                    self.t1_key_type_dropdown.currentText(),
                    self.t1_hex_key_file_path_display.text()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Key Conversion", "HEX to PEM conversion successful!")
                else:
                    QMessageBox.warning(self, "Key Conversion", retList[1])
        else:
            QMessageBox.warning(self, "Missing Input", "Please select the conversion mode and load appropriate key for conversion.")

    def t1_generate_hasher(self):
        key_type = self.t1_key_type_dropdown.currentText()
        selected_hash = self.t1_algorithm_dropdown.currentText()
        if key_type and selected_hash:
            self.t1_call_count += 1
            retList = interface.If_generateHasherLongMessage(key_type, selected_hash)
            if retList[0] == "Success":
                QMessageBox.information(self, "Generate Hasher", "Hasher generated successfully!")
            else:
                QMessageBox.warning(self, retList[0], retList[1])
        else:
            QMessageBox.information(self, "Generate Hasher", "Please select a valid key and Hash")

    def t1_update_hasher(self):
        if self.t1_call_count == 0:
            QMessageBox.warning(self, "No Hasher", "Please generate a hasher first.")
        elif not self.t1_input_file_path_display.text() or not self.t1_hasher_file_path.text():
            QMessageBox.warning(self, "Missing Input", "Please load an input file and the generated hasher file .")
        else:
            key_type = self.t1_key_type_dropdown.currentText()
            retList = interface.If_updateHasherLongMessage(key_type, self.t1_input_file_path_display.text(), self.t1_hasher_file_path.text())
            if retList[0] == "Success":
                QMessageBox.information(self, "Update Hasher", "Hasher updated with given data successfully!")
            else:
                QMessageBox.warning(self, retList[0], retList[1])

    def t1_generate_signature(self):
        if self.t1_key_type_dropdown.currentText() == "Symmetric key":
            QMessageBox.warning(self, "Warning", "Cannot sign using a Symmetric key")
        else:
            if "long" in self.t1_mode_dropdown.currentText():
                if self.t1_call_count < 1:
                    QMessageBox.warning(self, "Warning", "Please generate a hasher first.")
                elif not self.t1_private_key_file_path_display.text() or not self.t1_hasher_file_path.text():
                    QMessageBox.warning(self, "Missing Input", "Please load a Private key and a hasher file for generating a signature.")
                else:
                    retList = interface.If_generate_signForLongMessage(
                        self.t1_key_type_dropdown.currentText(),
                        self.t1_private_key_file_path_display.text(),
                        self.t1_hasher_file_path.text(),
                        self.t1_algorithm_dropdown.currentText()
                    )
                    if retList[0] == "Success":
                        self.t1_call_count = 0
                        QMessageBox.information(self, "Signature Generation", "Signature generated successfully!")
                    else:
                        QMessageBox.information(self, "Signature Generation", retList[1])
            else:
                if not self.t1_private_key_file_path_display.text() or not self.t1_input_file_path_display.text():
                    QMessageBox.warning(self, "Missing Input", "Please load a Private key and an input file for generating a signature.")
                else:
                    retList = interface.If_generate_sign(
                        self.t1_key_type_dropdown.currentText(),
                        self.t1_private_key_file_path_display.text(),
                        self.t1_input_file_path_display.text(),
                        self.t1_algorithm_dropdown.currentText()
                    )
                    if retList[0] == "Success":
                        QMessageBox.information(self, "Signature Generation", "Signature generated successfully!")
                    else:
                        QMessageBox.information(self, "Signature Generation", retList[1])

    def t1_verify_signature(self):
        if "long" in self.t1_algorithm_dropdown.currentText():
            if not self.t1_public_key_file_path_display.text() or not self.t1_hasher_file_path.text() or not self.t1_signature_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load the public key, a hasher file, and a signature file for generating a signature.")
            else:
                retList = interface.If_verify_signature_LongMessage(
                    self.t1_key_type_dropdown.currentText(),
                    self.t1_public_key_file_path_display.text(),
                    self.t1_hasher_file_path.text(),
                    self.t1_signature_file_path_display.text(),
                    self.t1_algorithm_dropdown.currentText()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Signature Verification", "Signature verified successfully!")
                else:
                    QMessageBox.warning(self, "Signature Verification", retList[1])
        else:
            if not self.t1_public_key_file_path_display.text() or not self.t1_input_file_path_display.text() or not self.t1_signature_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load the public key, an input file, and a signature file for generating a signature.")
            else:
                retList = interface.If_verify_signature(
                    self.t1_key_type_dropdown.currentText(),
                    self.t1_public_key_file_path_display.text(),
                    self.t1_input_file_path_display.text(),
                    self.t1_signature_file_path_display.text(),
                    self.t1_algorithm_dropdown.currentText()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Signature Verification", "Signature verified successfully!")
                else:
                    QMessageBox.warning(self, "Signature Verification", retList[1])

    def t2_load_iv_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Initialization Vector File', '', 'Initialization Vector Files (*.iv *.bin *.txt *.dat *.pem);;All Files (*)')
        if file_path:
            self.t2_iv_file_path_display.setText(file_path)

    def t2_load_encrypted_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Encrypted File', '', 'Encrypted Files (*.enc);;All Files (*)')
        if file_path:
            self.t2_encrypted_file_path_display.setText(file_path)

    def t2_load_hash_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open hash File', '', 'Hash Files (*.hash *.hsh *.txt *.dat *.bin);;All Files (*)')
        if file_path:
            self.t2_hash_file_path_display.setText(file_path)

    def t2_encrypt(self):
        if self.t2_rsa_oaep_radio.isChecked():
            if not self.t2_public_key_file_path_display.text() or not self.t2_input_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a RSA public key and an input file for encryption.")
            else:
                retList = interface.If_rsa_encrypt(
                    self.t2_public_key_file_path_display.text(),
                    self.t2_input_file_path_display.text(),
                    self.t2_algorithm_dropdown.currentText()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Encryption", "File encrypted successfully!")
                else:
                    QMessageBox.information(self, "Encryption", retList[1])
        else:
            if not self.t2_key_file_path_display.text() or not self.t2_input_file_path_display.text() or not self.t2_iv_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a key, an Initialization vector and an input file for encryption.")
            else:
                aes_algo = ""
                if self.t2_cbc_radio.isChecked():
                    aes_algo = "CBC"
                else:
                    aes_algo = "CTR"
                retList = interface.If_aes_encrypt(
                    self.t2_key_file_path_display.text(),
                    self.t2_input_file_path_display.text(),
                    self.t2_iv_file_path_display.text(),
                    aes_algo
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Encryption", "File encrypted successfully!")
                else:
                    QMessageBox.information(self, "Encryption", retList[1])

    def t2_decrypt(self):
        if self.t2_rsa_oaep_radio.isChecked():
            if not self.t2_private_key_file_path_display.text() or not self.t2_encrypted_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a RSA private key, an input file and an encrypted file for decryption.")
            else:
                retList = interface.If_rsa_decrypt(
                    self.t2_private_key_file_path_display.text(),
                    self.t2_encrypted_file_path_display.text(),
                    self.t2_algorithm_dropdown.currentText()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Decryption", "Decryption completed successfully!")
                else:
                    QMessageBox.information(self, "Decryption", retList[1])
        else:
            if not self.t2_key_file_path_display.text() or not self.t2_encrypted_file_path_display.text() or not self.t2_iv_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a key, an Initialization vector and an encrypted file for decryption.")
            else:
                aes_algo = ""
                if self.t2_cbc_radio.isChecked():
                    aes_algo = "CBC"
                else:
                    aes_algo = "CTR"

                retList = interface.If_aes_decrypt(
                    self.t2_key_file_path_display.text(),
                    self.t2_iv_file_path_display.text(),
                    self.t2_encrypted_file_path_display.text(),
                    aes_algo
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "Decryption", "File encrypted successfully!")
                else:
                    QMessageBox.information(self, "Decryption", retList[1])
    
    def t2_generate_hash(self):
        if not self.t2_input_file_path_display.text():
            QMessageBox.warning(self, "Missing Input", "Please load an input file for generating a hash.")
        else:
            retList = interface.If_generate_hash(
                self.t2_input_file_path_display.text(),
                self.t2_algorithm_dropdown.currentText()
            )
            if retList[0] == "Success":
                QMessageBox.information(self, "Generate Hash", "Hash generated successfully!")
            else:
                QMessageBox.information(self, "Generate Hash", retList[1])

    def t2_verify_hash(self):
        if not self.t2_input_file_path_display.text() or not self.t2_hash_file_path_display.text():
            QMessageBox.warning(self, "Missing Input", "Please load an input and a hash file for verifying the hash.")
        else:
            retList = interface.If_verify_hash(
                self.t2_input_file_path_display.text(),
                self.t2_hash_file_path_display.text(),
                self.t2_algorithm_dropdown.currentText()
            )
            if retList[0] == "Success":
                QMessageBox.information(self, "Verify Hash", "Hash verified!")
            else:
                QMessageBox.information(self, "Verify Hash", retList[1])

    def t3_load_verification_file(self, mode):
        if mode == "CMAC":
            file_path, _ = QFileDialog.getOpenFileName(self, 'Open CMAC Verification File', '', 'CMAC Files (*.cmac *.mac *.bin *.txt *.dat);;All Files (*)')
            if file_path:
                self.t3_cmac_verification_path_display.setText(file_path)
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, 'Open CRC Verification File', '', 'CRC Files (*.crc *.bin *.txt *.dat);;All Files (*)')
            if file_path:
                self.t3_crc_verification_path_display.setText(file_path)

    def t3_generate_time_stamp(self):
        timestamp = str(int(time.time()))
        self.t3_time_stamp_display.setText(timestamp)

    def t3_generate(self):
        if "cmac" in self.t3_mode_dropdown.currentText().lower():
            if self.t3_without_time_stamp_radio.isChecked():
                if not self.t3_key_file_path_display.text() or not self.t3_input_path_file_display.text():
                    QMessageBox.warning(self, "Missing Input", "Please load a key and an Input file for generating CMAC.")
                else:
                    retList = interface.If_generate_CMAC(
                        self.t3_key_file_path_display.text(),
                        self.t3_input_path_file_display.text()
                    )
                    if retList[0] == "Success":
                        QMessageBox.information(self, "CMAC Generation", "CMAC generated successfully!")
                    else:
                        QMessageBox.information(self, "CMAC Generation", retList[1])
            else:
                if not self.t3_key_file_path_display.text() or not self.t3_input_path_file_display.text() or not self.t3_time_stamp_display.text():
                    QMessageBox.warning(self, "Missing Input", "Please load a key and an Input file for generating CMAC.")
                else:
                    retList = interface.If_generate_cmac_with_time_stamp(
                        self.t3_key_file_path_display.text(),
                        self.t3_input_path_file_display.text(),
                        self.t3_time_stamp_display.text()
                    )
                    if retList[0] == "Success":
                        QMessageBox.information(self, "CMAC Generation", "CMAC with timestamp generated successfully!")
                    else:
                        QMessageBox.information(self, "CMAC Generation", retList[1])
        else:
            if not self.t3_input_path_file_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load an Input file for generating CRC.")
            else:
                retList = interface.If_generate_crc(
                    self.t3_input_path_file_display.text(),
                    self.t3_crc_algorithm_dropdown.currentText()
                )
                if retList[0] == "Success":
                    QMessageBox.information(self, "CRC Generation", "CRC generated successfully!")
                else:
                    QMessageBox.information(self, "CRC Generation", retList[1])

    def t3_verify(self):
        if "cmac" in self.t3_mode_dropdown.currentText().lower():
            if self.t3_without_time_stamp_radio.isChecked():
                if not self.t3_key_file_path_display.text() or not self.t3_input_path_file_display.text() or not self.t3_cmac_verification_path_display.text():
                    QMessageBox.warning(self, "Missing Input", "Please load a key and an Input file and a verification file for verifying CMAC.")
                else:
                    retList = interface.If_verify_cmac(
                        self.t3_key_file_path_display.text(),
                        self.t3_input_path_file_display.text(),
                        self.t3_cmac_verification_path_display.text()
                    )
                    if retList[0] == "Success":
                        QMessageBox.information(self, "CMAC Verification", "CMAC Verified successfully!")
                    else:
                        QMessageBox.information(self, "CMAC Verification", retList[1])
            else:
                if not self.t3_key_file_path_display.text() or not self.t3_input_path_file_display.text() or not self.t3_user_time_stamp_display.text() or not self.t3_user_time_threshold_display.text():
                    QMessageBox.warning(self, "Missing Input", "Please load a key and an Input file for generating CMAC.")
                else:
                    retList = interface.If_verify_cmac_with_time_stamp(
                        self.t3_key_file_path_display.text(),
                        self.t3_input_path_file_display.text(),
                        self.t3_cmac_verification_path_display.text(),
                        self.t3_user_time_stamp_display.text(),
                        self.t3_user_time_threshold_display.text()
                    )
                    if retList[0] == "Success":
                        QMessageBox.information(self, "CMAC Verification", "CMAC with timestamp Verified successfully!")
                    else:
                        QMessageBox.information(self, "CMAC Verification", retList[1])
        else:
            if not self.t3_input_path_file_display.text() or not self.t3_crc_verification_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load an Input file and a crc file for verifying CRC.")
            else:
                retList = interface.If_verify_crc(
                    self.t3_input_path_file_display.text(),
                    self.t3_crc_verification_path_display.text(),
                    self.t3_crc_algorithm_dropdown.currentText()
                )
                QMessageBox.information(self, f"{retList[0]}", f"{retList[1]}")

    def generate_random_bytes(self):
        interface.If_generate_random_bytes(self.t3_number_of_bytes_dropdown.currentText())
        QMessageBox.information(self, "Random Byte", "Random Bytes generated Successfully.")

# Main execution
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = mainWindow()
    ex.show()
    sys.exit(app.exec_())
