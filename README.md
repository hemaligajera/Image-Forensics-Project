# 🕵️‍♂️ Digital Image Forensics Analyzer

This is a Streamlit application for a Cyber Forensics & Investigation (CFI) project. It performs a multi-level analysis of digital images to uncover metadata, detect manipulation, and verify authenticity.

## 🚀 Features

* **Summary Dashboard:** At-a-glance metrics for EXIF tags, hidden data, and entropy.
* **File Integrity & Authenticity:**
    * Calculates **MD5** and **SHA-256** hashes.
    * Performs **File Signature Verification** (Magic Numbers) to check if the file extension is fake.
* **Metadata Analysis:**
    * Extracts all **EXIF tags**.
    * Finds and displays **GPS Geolocation** on an interactive map.
    * Extracts and shows the **embedded EXIF Thumbnail**.
* **Manipulation & Tampering Detection:**
    * **Error Level Analysis (ELA)** to visually identify parts of an image with different compression levels.
    * **JPEG Quantization Table Analysis** to detect signs of re-compression.
* **Hidden Data Detection:**
    * Scans for data hidden after the **End-of-File (EOF)** marker (steganography).
    * Performs **String Extraction** to find readable text hidden in the file's binary.

## 🛠️ How to Run

1.  Install the required libraries:
    ```
    pip install -r requirements.txt
    ```
2.  Run the Streamlit app:
    ```
    streamlit run main.py
    ```