import sys     # For system operations
import os      # For file path operations
import base64  # To display binary cipher data as readable text

# Importing GUI components
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QRadioButton,
    QLineEdit, QPushButton, QTextEdit, QLabel, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt  # For alignment flags

# -----------------------------------------------------------------------------
# MAIN APPLICATION
# -----------------------------------------------------------------------------
class FeistelCipherApp(QWidget):
    def __init__(self):                                   # Initializes variables and sets up the UI
        super().__init__()                                # Inherit methods from QWidget

        # Initialize variables to store encryption state
        self.master_key_int = 0                           # The user key
        self.rounds = 0                                   # Number of rounds
        self.round_keys = []                              # List to store generated sub-keys
        self.initUI()                                     # Build the User Interface

    def initUI(self):                                     #Sets up the window, layout, buttons, and input fields.
        self.setWindowTitle('Ahmet Salih Şenol-Y255033001-InfoSec Feistel Cipher Application V1.7')
        self.setGeometry(100, 100, 600, 750)              # x, y, width, height
        main_layout = QVBoxLayout()                       # Main layout

        # MODE SELECTION
        mode_box = QGroupBox("1. Operation Mode")         # Create container box with title for the Mode section
        mode_layout = QHBoxLayout()                       # Horizontal layout
        self.rb_encrypt = QRadioButton("Encrypt")         # Encrypt button
        self.rb_decrypt = QRadioButton("Decrypt")         # Decrypt button
        self.rb_ed = QRadioButton("Encrypt-Decrypt")      # Encrypt and Decrypt button
        self.rb_ed.setChecked(True)                       # Default selection
        mode_layout.addWidget(self.rb_encrypt)            # Add the radio button to the horizontal layout
        mode_layout.addWidget(self.rb_decrypt)
        mode_layout.addWidget(self.rb_ed)
        mode_box.setLayout(mode_layout)                   # Apply this horizontal layout to the GroupBox container.
        main_layout.addWidget(mode_box)                   # Add the GroupBox to the Main Window


        # KEY INPUT
        key_box = QGroupBox("2. Master Key (64-bit)")
        key_layout = QHBoxLayout()
        self.le_key = QLineEdit()                                         # Create a text input field for the user to type the key
        self.le_key.setPlaceholderText("Enter 8 characters ('MKey.123')") # Set gray hint text to guide the user on what to enter
        self.btn_load_key = QPushButton("Load from File")                 # Create button to allow loading the key from a text file
        self.btn_load_key.clicked.connect(self.load_key_from_file)        # Connect the button to the 'load_key_from_file' function
        key_layout.addWidget(self.le_key)
        key_layout.addWidget(self.btn_load_key)
        key_box.setLayout(key_layout)
        main_layout.addWidget(key_box)

        # ROUNDS SELECTION
        rounds_box = QGroupBox("3. Number of Rounds")
        rounds_layout = QHBoxLayout()                                    # Create horizontal layout to align radio buttons side by side
        self.rb_8_rounds = QRadioButton("8 Rounds")                      # Create radio buttons for 8 Rounds and 16 Rounds options
        self.rb_16_rounds = QRadioButton("16 Rounds")
        self.rb_8_rounds.setChecked(True)                                # Default selection 8 Rounds
        rounds_layout.addWidget(self.rb_8_rounds)
        rounds_layout.addWidget(self.rb_16_rounds)
        rounds_box.setLayout(rounds_layout)
        main_layout.addWidget(rounds_box)

        # --- INPUT TEXT ---
        input_box = QGroupBox("4. Input Text")
        input_layout = QVBoxLayout()
        self.te_input = QTextEdit()                                  # Create multi-line text input field for the user to type or paste text
        self.te_input.setPlaceholderText("Enter text here...")       # Set gray hint text to guide the user on what to enter
        self.btn_load_text = QPushButton("Load Text File")           # Create button to allow loading text from a file
        self.btn_load_text.clicked.connect(self.load_text_from_file) # Connect the button to the 'load_key_from_file' function
        input_layout.addWidget(self.te_input)
        input_layout.addWidget(self.btn_load_text)
        input_box.setLayout(input_layout)
        main_layout.addWidget(input_box)

        # --- ACTION BUTTONS ---
        action_layout = QHBoxLayout()
        self.btn_process = QPushButton("START PROCESS")              # Main process button
        self.btn_process.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.btn_process.clicked.connect(self.process_data)          # Connect the button to the main logic function 'process_data'
        self.btn_show_hex = QPushButton("Show Hex Blocks")           # Helper button to allow viewing the input text as Hexadecimal blocks
        self.btn_show_hex.clicked.connect(self.show_hex_blocks)
        self.btn_show_keys = QPushButton("Show Round Keys")          # Helper button to display the generated round keys
        self.btn_show_keys.clicked.connect(self.show_round_keys)
        action_layout.addWidget(self.btn_process)
        action_layout.addWidget(self.btn_show_hex)
        action_layout.addWidget(self.btn_show_keys)
        main_layout.addLayout(action_layout)

        # --- OUTPUT ---
        output_box = QGroupBox("5. Output")
        output_layout = QVBoxLayout()
        self.te_output = QTextEdit()                                    # Create text area to display the results
        self.te_output.setReadOnly(True)                                # User cannot edit the result manually
        self.btn_save_output = QPushButton("Save Output")               # Create button to allow saving the result to a text file
        self.btn_save_output.clicked.connect(self.save_output_to_file)  # Connect the button to the 'save_output_to_file' function
        output_layout.addWidget(self.te_output)
        output_layout.addWidget(self.btn_save_output)
        output_box.setLayout(output_layout)
        main_layout.addWidget(output_box)


        # --- STATUS BAR ---
        self.lbl_status = QLabel("Status: Ready")                       # Create label to display the current status of the application
        self.lbl_status.setAlignment(Qt.AlignCenter)                    # Center the text within the label
        self.lbl_status.setStyleSheet("border: 1px solid gray; padding: 5px;")
        main_layout.addWidget(self.lbl_status)                          # Add the status label to the bottom of the main layout
        # Main Layout
        self.setLayout(main_layout)                                     # Apply the fully constructed main layout to the application window

    # -----------------------------------------------------------------
    # CRYPTOGRAPHIC LOGIC
    # -----------------------------------------------------------------

    # Key Generator
    def key_schedule(self):            #Generates round keys from the Master Key
        keys = []
        key_64 = self.master_key_int   # Master key as integer
        mask_64 = (1 << 64) - 1        # Mask to keep it 64-bit
        mask_32 = (1 << 32) - 1        # Mask for 32-bit halves

        for i in range(self.rounds):
            shifted_key = ((key_64 << (i * 3)) & mask_64) | (key_64 >> (64 - (i * 3))) # Circular 3 Left Shift logic based on round index
            keys.append(shifted_key & mask_32)                                         # Take the lower 32 bits as the round key
        return keys

    # Round Function
    def round_function(self, r_32, key_32):                      #The 'F' function mixes the right half (R) with the Round Key
        mask_32 = (1 << 32) - 1
        shifted_r = ((r_32 << 5) & mask_32) | (r_32 >> (32 - 5)) # Circular shift the data block by 5 bits
        return shifted_r ^ key_32                                # XOR with the round key

    # Padding
    def pad(self, data):                                    # Applies PKCS#7 padding ensures the data length is a multiple of 8 bytes (64 bits)
        block_size = 8                                      # Define the block size as 8 bytes (64 bits)
        padding_len = block_size - (len(data) % block_size) # Calculate how many bytes are needed to make the length a multiple of 8
        padding = bytes([padding_len] * padding_len)        # Create padding bytes
        return data + padding                               # Append the padding to the original data and return it

    # Unpadding
    def unpad(self, data):                                  # Removes PKCS#7 padding after decryption
        if not data: return b''                             # Return empty bytes if the input is empty for check
        padding_len = data[-1]                              # The last byte tells us the padding length
        if padding_len > 8 or padding_len == 0:             # Validation for padding it must be between 1 and 8
            return data                                     # Return as is if padding looks invalid
        return data[:-padding_len]                          # Remove the padding bytes by slicing the array up to the padding start point

    # Main Feistel Proces
    def process_blocks(self, data, keys):                      # Core Feistel Loop. Processes data in 8-byte blocks
        processed_data = b''
        for i in range(0, len(data), 8):                       # Iterate over the data in chunks of 8 bytes
            block = data[i:i + 8]                              # Extract the current block
            block_int = int.from_bytes(block, 'big')  # Convert bytes to int
            L = (block_int >> 32) & 0xFFFFFFFF                 # Split into L and R halves (32 bits each)
            R = block_int & 0xFFFFFFFF

            for j in range(self.rounds):                       # Execute Rounds
                L_new = R                                      # L becomes the old R
                F_result = self.round_function(R, keys[j])     # Run F function
                R_new = L ^ F_result                           # XOR operation: New R = Old L XOR F(R, K)
                L, R = L_new, R_new                            # Update halves

            L, R = R, L                                                    # Final Swap
            final_int = (L << 32) | R                                      # Recombine L and R into a 64-bit block
            processed_data += final_int.to_bytes(8, 'big') # Convert the integer back to bytes
        return processed_data

    # Encryption
    def encrypt(self, plaintext):                                # Encryption function
        padded_text = self.pad(plaintext)                        # Apply padding first
        return self.process_blocks(padded_text, self.round_keys) # Process with keys

    # Decryption
    def decrypt(self, ciphertext):                               # Decryption function
        decryption_keys = self.round_keys[::-1]                  # For decryption, keys are used in REVERSE order
        decrypted_padded = self.process_blocks(ciphertext, decryption_keys)
        return self.unpad(decrypted_padded)                      # Remove padding


    # -----------------------------------------------------------------
    # UI EVENTS
    # -----------------------------------------------------------------

    # Load MasterKey File
    def load_key_from_file(self):                               #Opens file dialog to load key
        ''' Open the standard file dialog window and get the selected file path'''
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "Text Files (*.txt)")
        if file_path:                                           # Check if a valid file path was returned
            with open(file_path, 'r', encoding='utf-8') as f:   # Open the file in read mode ('r') using UTF-8 encoding to support all characters
                self.le_key.setText(f.read().strip())           # Read the file content, remove leading whitespace and insert into the input field

    # Load Text File Plain or Cipher (Cipher must be in Hexa)
    def load_text_from_file(self):                              #Opens file dialog to load input text
        ''' Open the standard file dialog window and get the selected file path'''
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Text File", "", "Text Files (*.txt)")
        if file_path:                                           # Check if a valid file path was returned
            with open(file_path, 'r', encoding='utf-8') as f:   # Open the file in read mode ('r') using UTF-8 encoding to support all characters
                self.te_input.setText(f.read())                 # Read the entire file content and insert it into the input text area

    # Save the Output as .txt File
    def save_output_to_file(self):                              # Saves the content of the output box to a file
        output_text = self.te_output.toPlainText()              # Retrieve the text currently displayed in the output text area
        if not output_text: return                              # If there is no text to save exit the function

        '''Open a standard 'Save As' dialog to let the user choose the file name and location'''
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Result", "result.txt", "Text Files (*.txt)")
        if file_path:                                                                  # If a valid file path is selected
            with open(file_path, 'w', encoding='utf-8') as f:                          # Open the file in write mode ('w') using UTF-8 encoding
                f.write(output_text)                                                   # Write the output text into the file
        QMessageBox.information(self, "Success", "File saved successfully.") # Display a success message to the user

    # Show Input Hex Blocks
    def show_hex_blocks(self):                # Shows how input text is divided into hex blocks
        text = self.te_input.toPlainText()    # Retrieve text from the input field
        if not text: return                   # Exit if input is empty

        data = self.pad(text.encode('utf-8')) # Convert text to UTF-8 bytes and apply padding
        msg = "Memory Blocks (64-bit):\n"
        for i in range(0, len(data), 8):                          # Iterate through the byte data in steps of 8 (64 bits)
            block = data[i:i + 8]                                 # Extract the current 8-byte block
            msg += f"Block {i // 8 + 1}: {block.hex().upper()}\n" # Append the formatted Hex string to the message

        QMessageBox.information(self, "Hex View", msg)       # Display the formatted blocks in a pop-up window

    # Show Round Keys in Hexa
    def show_round_keys(self):                                    # Shows the round keys
        if not self.round_keys:                                   # Check if the round keys list is empty
            QMessageBox.warning(self, "Warning", "Please run a process first to generate keys.")
            return

        msg = ""
        for i, key in enumerate(self.round_keys):                 # Loop through each generated key to format it for display
            msg += f"Round {i + 1}: 0x{key:08X}\n"                # Format the key as an 8-digit Hexadecimal string

        QMessageBox.information(self, "Round Keys", msg)     # Display the list of keys in a pop-up window

# ---------------------------------
#          MAIN CODE
# ---------------------------------
    def process_data(self):                                             #Executed when 'START PROCESS' is clicked
        # 1. Key
        # 1.1 Validate and Prepare Key
        key_str = self.le_key.text()                                    # Retrieve the text entered the key input field
        if not key_str:                                                 # Check if the key field is empty
            QMessageBox.critical(self, "Error", "Please enter a Master Key!")
            return

        # 1.2 Round Keys Generate
        key_bytes = key_str.encode('utf-8')                             # Convert the string key to bytes using UTF-8 encoding
        if len(key_bytes) < 8:                                          # Ensure the key is exactly 8 bytes (64 bits) long
            key_bytes = key_bytes.ljust(8, b'\x00')     # If too short, pad with null bytes (0x00) until it is 8 bytes long
        else:
            key_bytes = key_bytes[:8]                                   # If too long truncate it to keep only the first 8 bytes

        self.master_key_int = int.from_bytes(key_bytes, 'big') # Convert the 8-byte key into a single large integer for bitwise operations
        self.rounds = 16 if self.rb_16_rounds.isChecked() else 8        # Determine the number of rounds
        self.round_keys = self.key_schedule()                           #Generate Round Keys

        # 1.3 Get Input
        input_txt = self.te_input.toPlainText()                         # Retrieve the text entered the input box
        if not input_txt:                                               # Exit if the input text is empty
            QMessageBox.critical(self, "Error", "Input text is empty!")
            return

        # 2. Execute Mode
        try:
            # 2.1 ENCRYPT MODE
            if self.rb_encrypt.isChecked():                            # Check if the "Encrypt" radio button is selected
                raw_bytes = input_txt.encode('utf-8')                  # Convert the input text string into raw bytes using UTF-8 encoding
                enc_bytes = self.encrypt(raw_bytes)                    # Perform the encryption on the byte data

                b64_str = base64.b64encode(enc_bytes).decode('ascii')  # Convert to Base64 for readable display
                self.te_output.setText(b64_str)                        # Display the Base64 result in the output text area
                self.lbl_status.setText("Status: Encryption Successful")

            # 2.2 DECRYPT MODE
            elif self.rb_decrypt.isChecked():                          # Check if the "Decrypt" radio button is selected
                try:                                                   # Input must be Base64
                    enc_bytes = base64.b64decode(input_txt)            # Decode it back into raw encrypted bytes
                except:                                                # Show an error if the input string is not valid Base64
                    QMessageBox.critical(self, "Error", "Input is not valid Base64!")
                    return

                dec_bytes = self.decrypt(enc_bytes)                    # Perform the decryption on the raw bytes
                try:                                                   # Convert the decrypted binary data back into readable UTF-8 text
                    plain_text = dec_bytes.decode('utf-8')
                    self.te_output.setText(plain_text)                 # Display the clear text in the output box
                    self.lbl_status.setText("Status: Decryption Successful ")
                except UnicodeDecodeError:                             # If the key was wrong, the output will be random garbage bytes, not valid text
                    self.te_output.setText(f"[ERROR] Could not decode text. Wrong Key?\nHex Output: {dec_bytes.hex()}")
                    self.lbl_status.setText("Status: Error (Wrong Key?)")

            # 2.3 ED MODE
            elif self.rb_ed.isChecked():                                # Check if the "ED" radio button is selected
                # Encrypt
                raw = input_txt.encode('utf-8')                         # Convert input string to raw bytes
                enc = self.encrypt(raw)                                 # Perform encryption
                b64 = base64.b64encode(enc).decode('ascii')             # Convert to Base64 for display

                # Decrypt
                dec = self.decrypt(enc)                                 # Decrypt the encrypted binary data
                dec_txt = dec.decode('utf-8')                           # Decode bytes back to a UTF-8 string

                # Output
                report = (f"--- ORIGINAL ---\n{input_txt}\n\n"          # Display the output in the output box
                          f"--- ENCRYPTED ---\n{b64}\n\n"
                          f"--- DECRYPTED ---\n{dec_txt}")
                self.te_output.setText(report)

                # Compare
                if input_txt == dec_txt:                                #Compare the original text with the decrypted text to ensure integrity
                    self.lbl_status.setText("Status: Succesfull")
                else:
                    self.lbl_status.setText("Status: Failed")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

# -----------------------------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    app = QApplication(sys.argv) # Initialize Qt Application
    window = FeistelCipherApp()  # Create Main Window
    window.show()                # Show Window
    sys.exit(app.exec())         # Execute Event Loop