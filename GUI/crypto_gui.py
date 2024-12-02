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
            "Generate Sign",
            "Verify Sign",
            "Generate Sign for Long Message",
            "Verify Sign for Long Message"
        ])
        self.t1_mode_dropdown.currentTextChanged.connect(lambda: self.t1_update_mode(self.t1_mode_dropdown.currentText()))
        self.t1_mode_dropdown.currentTextChanged.connect(lambda: self.update_algorithm_options(self.t1_get_selected_key_type()))
        self.t1_call_count = 0

        # Key Type Selection
        self.t1_key_type_label = QLabel("Key Type:")
        self.t1_rsa_radio = QRadioButton("RSA")
        self.t1_ecdsa_radio = QRadioButton("ECDSA")
        self.t1_ed25519_radio = QRadioButton("ED25519")
        self.t1_rsa_radio.setChecked(True)

        # Algorithm Dropdown
        self.t1_algorithm_label = QLabel("Algorithm:")
        self.t1_algorithm_dropdown = QComboBox()
        self.update_algorithm_options("RSA")  # Default for RSA
        
        # Radio button connections to update algorithm options
        self.t1_rsa_radio.toggled.connect(lambda: self.update_algorithm_options("RSA"))
        self.t1_ecdsa_radio.toggled.connect(lambda: self.update_algorithm_options("ECDSA"))
        self.t1_ed25519_radio.toggled.connect(lambda: self.update_algorithm_options("ED25519"))
        self.t1_rsa_radio.toggled.connect(lambda: self.t1_update_mode(self.t1_mode_dropdown.currentText()))

        # Components for Keys & Signature Mode
        self.t1_generate_key_btn = QPushButton("Generate Key")
        self.t1_generate_key_btn.clicked.connect(self.t1_generate_key)
        self.t1_key_type_label = QLabel("key type:")
        self.t1_key_file_label = QLabel("Load Key")
        self.t1_input_file_label = QLabel("Input File:")
        self.t1_hasher_file_label = QLabel("Hasher File:")
        self.t1_signature_file_label = QLabel("Signature File:")

        self.t1_private_key_file_btn = QPushButton("Load Private Key")
        self.t1_private_key_file_btn.clicked.connect(partial(self.load_private_key, "tab1"))
        self.t1_private_key_file_path_display = QLineEdit()
        self.t1_private_key_file_path_display.setReadOnly(True)

        self.t1_public_key_file_btn = QPushButton("Load Public Key")
        self.t1_public_key_file_btn.clicked.connect(partial(self.load_public_key, "tab1"))
        self.t1_public_key_file_path_display = QLineEdit()
        self.t1_public_key_file_path_display.setReadOnly(True)

        self.t1_Key_size_label = QLabel("Key size:")
        self.t1_key_size_dropdown = QComboBox()
        self.t1_key_size_dropdown.addItems(["256", "512", "1024"])
        
        self.t1_generate_signature_btn = QPushButton("Generate Signature")
        self.t1_generate_signature_btn.clicked.connect(self.t1_generate_signature)

        self.t1_signature_file_btn = QPushButton("Load Signature File")
        self.t1_signature_file_btn.clicked.connect(self.t1_load_signature_file)
        self.t1_signature_file_path_display = QLineEdit()
        self.t1_signature_file_path_display.setReadOnly(True)

        self.t1_verify_signature_btn = QPushButton("Verify Signature")
        self.t1_verify_signature_btn.clicked.connect(self.t1_verify_signature)

        self.t1_input_file_btn = QPushButton("Load Input File")
        self.t1_input_file_btn.clicked.connect(partial(self.load_input_file, "tab1"))
        self.t1_input_file_path_display = QLineEdit()
        self.t1_input_file_path_display.setReadOnly(True)

        # Long message-related buttons
        self.t1_generate_hasher_btn = QPushButton("Generate Hasher")
        self.t1_generate_hasher_btn.clicked.connect(self.t1_generate_hasher)

        self.t1_update_hasher_btn = QPushButton("Update Hasher")
        self.t1_update_hasher_btn.clicked.connect(self.t1_update_hasher)

        self.t1_hasher_file_btn = QPushButton("Load Hasher File")
        self.t1_hasher_file_btn.clicked.connect(self.t1_load_hasher_file)
        self.t1_hasher_file_path = QLineEdit()
        self.t1_hasher_file_path.setReadOnly(True)

        # Layout
        t1_layout = QGridLayout()
        t1_layout.setSpacing(10)

        # Add mode selector
        t1_layout.addWidget(self.t1_mode_label, 0, 0)
        t1_layout.addWidget(self.t1_mode_dropdown, 0, 1, 1, 3)

        # Key Type Selection
        t1_layout.addWidget(self.t1_key_type_label, 1, 0)
        t1_layout.addWidget(self.t1_rsa_radio, 1, 1)
        t1_layout.addWidget(self.t1_ecdsa_radio, 1, 2)
        t1_layout.addWidget(self.t1_ed25519_radio, 1, 3)

        # Algorithm Dropdown
        t1_layout.addWidget(self.t1_algorithm_label, 2, 0)
        t1_layout.addWidget(self.t1_algorithm_dropdown, 2, 1, 1, 3)

        t1_layout.addWidget(self.t1_Key_size_label, 3, 0)
        t1_layout.addWidget(self.t1_key_size_dropdown, 3, 1, 1, 3)

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
        self.t2_algorithm_dropdown.addItems(['SHA-224','SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'blake2b', 'blake2s', 'md5', 'SHA-1'])

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

        t2_layout.addWidget(self.t2_algorithm_label, 1, 0)
        t2_layout.addWidget(self.t2_algorithm_dropdown, 1, 1, 1, 3)
        t2_layout.addWidget(self.t2_encryption_mode_label, 1, 0)
        t2_layout.addWidget(self.t2_cbc_radio, 1, 1)
        t2_layout.addWidget(self.t2_ctr_radio, 1, 2)
        t2_layout.addWidget(self.t2_rsa_oaep_radio, 1, 3)

        t2_layout.addWidget(self.t2_input_file_label, 2, 0)
        t2_layout.addWidget(self.t2_input_file_btn, 2, 1)
        t2_layout.addWidget(self.t2_input_file_path_display, 2, 2, 1, 2)

        t2_layout.addWidget(self.t2_iv_file_label, 3, 0)
        t2_layout.addWidget(self.t2_iv_file_btn, 3, 1)
        t2_layout.addWidget(self.t2_iv_file_path_display, 3, 2, 1, 2)

        t2_layout.addWidget(self.t2_key_file_label, 4, 0)
        t2_layout.addWidget(self.t2_key_file_btn, 4, 1)
        t2_layout.addWidget(self.t2_key_file_path_display, 4, 2, 1, 2)
        t2_layout.addWidget(self.t2_private_key_file_btn, 4, 1)
        t2_layout.addWidget(self.t2_private_key_file_path_display, 4, 2, 1, 2)
        t2_layout.addWidget(self.t2_public_key_file_btn, 4, 1)
        t2_layout.addWidget(self.t2_public_key_file_path_display, 4, 2, 1, 2)
        

        t2_layout.addWidget(self.t2_encrypted_file_label, 5, 0)
        t2_layout.addWidget(self.t2_encrypted_file_btn, 5, 1)
        t2_layout.addWidget(self.t2_encrypted_file_path_display, 5, 2, 1, 2)

        t2_layout.addWidget(self.t2_hash_file_label, 5, 0)
        t2_layout.addWidget(self.t2_hash_file_btn, 5, 1)
        t2_layout.addWidget(self.t2_hash_file_path_display, 5, 2, 1, 2)

        t2_layout.addWidget(self.t2_encrypt_btn, 6, 0, 1, 4)
        t2_layout.addWidget(self.t2_decrypt_btn, 6, 0, 1, 4)
        t2_layout.addWidget(self.t2_generate_hash_btn, 7, 0, 1, 4)
        t2_layout.addWidget(self.t2_verify_hash_btn, 7, 0, 1, 4)

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
            "CRC-32", "CRC-64", 
            "ETC", "ETC", 
            "ETC"
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
        self.t3_random_label = QLabel("Random Numbers/Bytes:")
        self.t3_random_number_btn = QPushButton("Generate Random Numbers")
        self.t3_random_number_btn.clicked.connect(self.generate_random_numbers)
        self.t3_random_output_display = QLineEdit()
        self.t3_random_output_display.setReadOnly(True)

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

        t3_layout.addWidget(self.t3_random_label, 8, 0)
        t3_layout.addWidget(self.t3_random_number_btn, 8, 1)
        t3_layout.addWidget(self.t3_random_output_display, 8, 2, 1, 2)

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
        
        <h2>Keys & Signature</h2>
        <ul>
            <li><b>Key Generation:</b> Generate RSA, ECDSA, or ED25519 keys.</li>
            <li><b>Generate Sign:</b> Generate a digital signature for a given input file.</li>
            <li><b>Verify Sign:</b> Verify a digital signature for a given input file.</li>
            <li><b>Generate Sign for Long Message:</b> Generate a digital signature for a long message.</li>
            <li><b>Verify Sign for Long Message:</b> Verify a digital signature for a long message.</li>
        </ul>
        
        <h2>Encrypt/Decrypt & Hashing</h2>
        <ul>
            <li><b>Encryption:</b> Encrypt a given input file using a specified algorithm.</li>
            <li><b>Decryption:</b> Decrypt a given encrypted file using a specified algorithm.</li>
            <li><b>Generate Hash:</b> Generate a hash for a given input file.</li>
            <li><b>Verify Hash:</b> Verify a hash for a given input file.</li>
        </ul>
        
        <h2>CRC & CMAC & Random</h2>
        <ul>
            <li><b>Generate CMAC:</b> Generate a CMAC for a given input file.</li>
            <li><b>Verify CMAC:</b> Verify a CMAC for a given input file.</li>
            <li><b>Generate CRC:</b> Generate a CRC for a given input file.</li>
            <li><b>Verify CRC:</b> Verify a CRC for a given input file.</li>
            <li><b>Generate Random Numbers:</b> Generate random numbers or bytes.</li>
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
        key_generation_mode = "key" in mode.lower()
        generate_sign_mode = "generate" in mode.lower() and "long" not in mode.lower()
        generate_long_sign_mode = "generate" in mode.lower() and "long" in mode.lower()
        verify_sign_mode = "verify" in mode.lower() and "long" not in mode.lower()
        verify_long_sign_mode = "verify" in mode.lower() and "long" in mode.lower()

        # Combined modes
        generate_mode = generate_sign_mode or generate_long_sign_mode
        verify_mode = verify_sign_mode or verify_long_sign_mode

        # Update visibility for each component
        # Key generation components
        self.t1_generate_key_btn.setVisible(key_generation_mode)
        self.t1_Key_size_label.setVisible(key_generation_mode and self.t1_rsa_radio.isChecked())
        self.t1_key_size_dropdown.setVisible(key_generation_mode and self.t1_rsa_radio.isChecked())

        # Private key (generation or signature generation modes)
        self.t1_private_key_file_btn.setVisible(generate_mode)
        self.t1_private_key_file_path_display.setVisible(generate_mode)
        self.t1_generate_signature_btn.setVisible(generate_mode)
        self.t1_key_file_label.setVisible(generate_mode or verify_mode)
        
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
        self.t1_input_file_label.setVisible(not key_generation_mode and not verify_long_sign_mode)
        self.t1_input_file_btn.setVisible(not key_generation_mode and not verify_long_sign_mode)
        self.t1_input_file_path_display.setVisible(not key_generation_mode and not verify_long_sign_mode)

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
        self.t2_decrypt_btn.setVisible(is_decryption_mode)
        self.t2_encrypted_file_label.setVisible(is_decryption_mode)
        self.t2_encrypted_file_btn.setVisible(is_decryption_mode)
        self.t2_encrypted_file_path_display.setVisible(is_decryption_mode)
        
        self.t2_cbc_radio.setVisible(not is_hash_mode)
        self.t2_ctr_radio.setVisible(not is_hash_mode)
        self.t2_rsa_oaep_radio.setVisible(not is_hash_mode)
        self.t2_algorithm_label.setVisible(is_hash_mode)
        self.t2_algorithm_dropdown.setVisible(is_hash_mode)
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

        self.t3_key_file_label.setVisible(is_generate_mode and is_cmac_mode)
        self.t3_key_file_btn.setVisible(is_generate_mode and is_cmac_mode)
        self.t3_key_file_path_display.setVisible(is_generate_mode and is_cmac_mode)

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

        self.t3_random_label.setVisible(is_random_mode)
        self.t3_random_number_btn.setVisible(is_random_mode)
        self.t3_random_output_display.setVisible(is_random_mode)

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

    def update_algorithm_options(self, key_type):
        """Update dropdown based on the mode and selected key type."""
        current_mode = self.t1_mode_dropdown.currentText()
        self.t1_algorithm_dropdown.clear()

        if "Key" in current_mode:
            if key_type == "RSA":
                self.t1_algorithm_dropdown.addItems(["RSA-OAEP", "RSA-PSS"])
            elif key_type == "ECDSA":
                self.t1_algorithm_dropdown.addItems(["SECP192R1","SECP256R1","SECP384R1","SECP521R1","SECP256K1"])
            else:
                pass
        else:
            self.t1_algorithm_dropdown.addItems(["SHA-256", "SHA-384", "SHA-512"])

    def t1_get_selected_key_type(self):
        if self.t1_rsa_radio.isChecked():
            return "RSA"
        elif self.t1_ecdsa_radio.isChecked():
            return "ECDSA"
        elif self.t1_ed25519_radio.isChecked():
            return "ED25519"
        return "RSA"  # Default to RSA if none are checked

    def t1_generate_key(self):
        QMessageBox.information(self, "Key Generation", "Key generated successfully!")

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

    def t1_load_signature_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Signature File', '', 'All Files (*)')
        if file_path:
            self.t1_signature_file_path_display.setText(file_path)

    def t1_generate_hasher(self):
        self.t1_call_count += 1
        QMessageBox.information(self, "Generate Hasher", "Hasher generated successfully!")
        pass

    def t1_update_hasher(self):
        if self.t1_call_count == 0:
            QMessageBox.warning(self, "No Hasher", "Please generate a hasher first.")
        elif not self.t1_input_file_path_display.text() and not self.t1_hasher_file_path.text():
            QMessageBox.warning(self, "Missing Input", "Please load an input file and the generated hasher file .")
        else:
            QMessageBox.information(self, "Update Hasher", "Hasher updated with given data successfully!")

    def t1_load_hasher_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open hasher File', '', 'Hash Files (*.hash *.hsh *.txt *.dat *.bin);;All Files (*)')
        if file_path:
            self.t1_hasher_file_path.setText(file_path)

    def t1_generate_signature(self):
        if "long" in self.t1_mode_dropdown.currentText():
            if not self.t1_private_key_file_path_display.text() or not self.t1_hasher_file_path.text():
                QMessageBox.warning(self, "Missing Input", "Please load a Private key and a hasher file for generating a signature.")
                print(self.t1_call_count, "long sign mode")
                self.t1_call_count = 0
            else:
                QMessageBox.information(self, "Signature Generation", "Signature generated successfully!")
        else:
            if not self.t1_private_key_file_path_display.text() or not self.t1_input_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a Private key and an input file for generating a signature.")
            else:
                QMessageBox.information(self, "Signature Generation", "Signature generated successfully!")

    def t1_verify_signature(self):
        if not self.t1_public_key_file_path_display.text() or not self.t1_input_file_path_display.text() or not self.t1_signature_file_path_display.text():
            QMessageBox.warning(self, "Missing Input", "Please load the public key, an input file, and a signature file for generating a signature.")
        else:
            QMessageBox.information(self, "Signature Verification", "Signature verified successfully!")

    def load_key_file(self, tab):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Key File', '', 'Key Files (*.key *.pem);;All Files (*)')
        if tab == "tab2":
            self.t2_key_file_path_display.setText(file_path)
        else:
            self.t3_key_file_path_display.setText(file_path)

    def t2_load_iv_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Initialization Vector File', '', 'Initialization Vector Files (*.iv *.bin *.txt *.dat *.pem);;All Files (*)')
        if file_path:
            self.t2_iv_file_path_display.setText(file_path)

    def t2_encrypt(self):
        if self.t2_rsa_oaep_radio.isChecked():
            if not self.t2_public_key_file_path_display.text() or not self.t2_input_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a RSA public key and an input file for encryption.")
        else:   
            if not self.t2_key_file_path_display.text() or not self.t2_input_file_path_display.text() or not self.t2_iv_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a key, an Initialization vector and an input file for encryption.")

        QMessageBox.information(self, "Encryption", "File encrypted successfully!")

    def t2_load_encrypted_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Encrypted File', '', 'Encrypted Files (*.enc);;All Files (*)')
        if file_path:
            self.t2_encrypted_file_path_display.setText(file_path)

    def t2_load_hash_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open hash File', '', 'Hash Files (*.hash *.hsh *.txt *.dat *.bin);;All Files (*)')
        if file_path:
            self.t1_hasher_file_path.setText(file_path)

    def t2_decrypt(self):
        if self.t2_rsa_oaep_radio.isChecked():
            if not self.t2_private_key_file_path_display.text() or not self.t2_input_file_path_display.text() or not self.t2_encrypted_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a RSA private key, an input file and an encrypted file for decryption.")
        else:
            if not self.t2_key_file_path_display() or not self.t2_encrypted_file_path_display.text() or not self.t2_iv_file_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a key, an Initialization vector and an encrypted file for decryption.")
        
        QMessageBox.information(self, "Decryption", "Decryption completed successfully!")
    
    def t2_generate_hash(self):
        if not self.t2_input_file_path_display.text():
            QMessageBox.warning(self, "Missing Input", "Please load an input file for generating a hash.")
        else:
            QMessageBox.information(self, "Generate Hash", "Hash generated successfully!")

    def t2_verify_hash(self):
        if not self.t2_input_file_path_display.text() and not self.t2_hash_file_path_display.text():
            QMessageBox.warning(self, "Missing Input", "Please load an input and a hash file for verifying the hash.")
        else:
            QMessageBox.information(self, "Verify Hash", "Hash verified!")

        QMessageBox.information(self, "Verify Hash", "Incorrect hash!")

    def t3_generate_time_stamp(self):
        timestamp = str(int(time.time()))
        self.t3_time_stamp_display.setText(timestamp)

    def t3_generate(self):
        if "cmac" in self.t3_mode_dropdown.currentText().lower():
            if not self.t3_key_file_path_display.text() and not self.t3_input_path_file_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a key and an Input file for generating CMAC.")
            else:
                QMessageBox.information(self, "CMAC Generation", "CMAC generated successfully!")
        else:
            if not self.t3_input_path_file_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load an Input file for generating CRC.")
            else:
                QMessageBox.information(self, "CRC Generation", "CRC generated successfully!")

    def t3_load_verification_file(self, mode):
        if mode == "CMAC":
            file_path, _ = QFileDialog.getOpenFileName(self, 'Open CMAC Verification File', '', 'CMAC Files (*.cmac *.mac *.bin *.txt *.dat);;All Files (*)')
            if file_path:
                self.t3_cmac_verification_path_display.setText(file_path)
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, 'Open CRC Verification File', '', 'CRC Files (*.crc *.bin *.txt *.dat);;All Files (*)')
            if file_path:
                self.t3_crc_verification_path_display.setText(file_path)

    def t3_verify(self):
        if "cmac" in self.t3_mode_dropdown.currentText().lower():
            if not self.t3_key_file_path_display.text() and not self.t3_input_path_file_display.text() and not self.t3_cmac_verification_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load a key, an Input file and a cmac file for verifying CMAC.")
            else:
                QMessageBox.information(self, "CMAC Verification", "CMAC verified successfully!")
        else:
            if not self.t3_input_path_file_display.text() and not self.t3_crc_verification_path_display.text():
                QMessageBox.warning(self, "Missing Input", "Please load an Input file and a crc file for verifying CRC.")
            else:
                QMessageBox.information(self, "CRC Verification", "CRC verified successfully!")

    def generate_random_numbers(self):
        """Generate random numbers."""
        random_number = 100
        self.t3_random_output_display.setText(random_number)
        
    
# Main execution
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = mainWindow()
    ex.show()
    sys.exit(app.exec_())
