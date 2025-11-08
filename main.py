# Import necessary libraries
import streamlit as st
from PIL import Image, ExifTags, ImageChops, ImageOps  # Pillow for image processing
import hashlib  # For generating MD5 and SHA256 hashes
import pandas as pd  # For displaying data in tables (DataFrames)
from datetime import datetime  # For timestamps
import io  # For handling in-memory byte streams
import math  # For entropy calculation
import re  # For regular expressions (used in string extraction)

# --------------------------------------------
# 🎨 PAGE CONFIGURATION
# --------------------------------------------
# Set up the basic properties of the Streamlit page
st.set_page_config(
    page_title="Image Forensics Analyzer",
    page_icon="🕵️‍♂️",  # Favicon
    layout="wide"  # Use the full width of the screen
)

# --------------------------------------------
# 💅 CUSTOM STYLING (CSS)
# --------------------------------------------
# Inject custom CSS to improve the look and feel
st.markdown("""
<style>
    /* Set a light grey background for the main app area to make 'cards' pop */
    .main {
        background-color: #F0F2F6;
    }
    
    /* Custom header for the file uploader */
    .uploader-header {
        font-size: 28px;
        font-weight: 600;
        color: #1F2937;
        margin-bottom: -10px; /* Pulls the uploader widget closer */
    }

    /* Hide the default Streamlit footer */
    footer {visibility: hidden;}
    
    /* Style the tabs for a cleaner look */
    button[data-baseweb="tab"] {
        font-size: 16px;
        font-weight: 600;
        background-color: #E0E0E0;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        background-color: #FFFFFF; /* Make the active tab white */
    }
</style>
""", unsafe_allow_html=True)


# --------------------------------------------
# 🧠 HELPER FUNCTIONS (ANALYSIS TOOLS)
# --------------------------------------------

def calculate_entropy(data):
    """
    Calculate the Shannon entropy of a given block of bytes.
    Entropy is a measure of randomness. High entropy (near 8.0)
    can suggest encrypted or compressed data.
    """
    if not data:
        return 0
    
    # Count the frequency of each byte (0-255)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Calculate the probability of each byte
    freq = [count / len(data) for count in byte_counts if count > 0]
    
    # Calculate Shannon entropy
    return -sum(f * math.log2(f) for f in freq)

def perform_ela(original_image, quality=90):
    """
    Performs Error Level Analysis (ELA) on an image.
    ELA resaves the image at a specific JPEG quality and finds the
    difference between the original and the resave. Edited areas
    will often have a different compression history and "light up".
    """
    try:
        # ELA only works on RGB or L (grayscale) modes
        if original_image.mode not in ['RGB', 'L']:
            original_image = original_image.convert('RGB')
            
        # Create an in-memory buffer to save the resaved image
        buffer = io.BytesIO()
        
        # Resave the image as JPEG with the specified quality
        original_image.save(buffer, format='JPEG', quality=quality)
             
        # Rewind the buffer and open the resaved image
        buffer.seek(0)
        resaved_image = Image.open(buffer)
        
        # Ensure both images are in the same mode for comparison
        if original_image.mode != resaved_image.mode:
            original_image = original_image.convert('RGB')
            resaved_image = resaved_image.convert('RGB')
            
        # Find the absolute difference between the pixels
        ela_image = ImageChops.difference(original_image, resaved_image)
        
        # Brighten the ELA image to make subtle differences visible
        ela_image = ImageOps.autocontrast(ela_image, 10)
        
        return ela_image
    except Exception as e:
        # Log an error if ELA fails (e.g., on incompatible formats)
        st.error(f"ELA Error: {e}")
        return None

def extract_strings(file_bytes, min_len=8):
    """
    Extracts all human-readable ASCII strings from the file's binary data.
    This can reveal software history, comments, or hidden messages.
    """
    try:
        # Use regex to find sequences of printable ASCII characters
        ascii_strings = re.findall(b"[\x20-\x7E]{%d,}" % min_len, file_bytes)
        # Decode the byte strings into regular Python strings
        decoded_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        return decoded_strings
    except Exception as e:
        return [f"Error during string extraction: {e}"]

def get_exif_thumbnail(exif_data):
    """
    Attempts to extract the embedded thumbnail image from the EXIF data.
    Sometimes an edited image forgets to update the thumbnail.
    """
    try:
        # The 'thumbnail' key is a special tag in Pillow's EXIF data
        if 'thumbnail' in exif_data:
            thumbnail_bytes = exif_data['thumbnail']
            # Open the thumbnail bytes as a new image
            thumbnail_image = Image.open(io.BytesIO(thumbnail_bytes))
            return thumbnail_image
    except Exception:
        # Fail silently if no thumbnail is found or it's corrupted
        return None
    return None

def convert_gps_to_decimal(gps_info):
    """
    Converts GPS coordinates from EXIF's DMS (Degrees, Minutes, Seconds)
    format to simple Decimal Degrees (DD) for mapping.
    """
    
    # Helper for converting one coordinate (lat or lon)
    def to_decimal(dms, ref):
        try:
            # EXIF stores DMS as a tuple of rational numbers (numerator/denominator)
            degrees = dms[0].numerator / dms[0].denominator
            minutes = dms[1].numerator / dms[1].denominator
            seconds = dms[2].numerator / dms[2].denominator
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            
            # South and West coordinates are negative
            if ref in ['S', 'W']:
                decimal = -decimal
            return decimal
        except Exception:
            return None

    try:
        # Get latitude (Tag 2) and its reference (Tag 1: N/S)
        lat = to_decimal(gps_info.get(2), gps_info.get(1))
        # Get longitude (Tag 4) and its reference (Tag 3: E/W)
        lon = to_decimal(gps_info.get(4), gps_info.get(3))
        
        if lat is not None and lon is not None:
            return lat, lon
    except Exception:
        # Fail silently if GPS data is missing or malformed
        pass
    return None, None

def verify_file_signature(file_bytes, file_extension):
    """
    Checks the file's "magic numbers" (first few bytes) to verify its
    true file type against its reported extension (e.g., .jpg).
    This detects if a file is misnamed (e.g., an .exe renamed to .jpg).
    """
    # A dictionary of known "magic number" signatures for image files
    MAGIC_NUMBERS = {
        "JPG": [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe2', b'\xff\xd8\xff\xe3', b'\xff\xd8\xff\xdb'],
        
        # --- THIS LINE IS FIXED ---
        # All \d8 (d-eight) are now \xd8 (hex-d-eight)
        "JPEG": [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe2', b'\xff\xd8\xff\xe3', b'\xff\xd8\xff\xdb'],
        
        "PNG": [b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a']
    }
    
    reported_type = file_extension.upper()
    
    # If we don't have this extension in our dictionary, skip the check
    if reported_type not in MAGIC_NUMBERS:
        return "Not_Checked"
    
    # Check if the file's starting bytes match any known signature
    for signature in MAGIC_NUMBERS[reported_type]:
        if file_bytes.startswith(signature):
            return "Pass"  # It's a match
            
    # No match found
    return "Fail"

def analyze_quantization_tables(image):
    """
    Extracts and analyzes JPEG quantization tables.
    Different cameras and software (like Photoshop) use different tables.
    Inconsistencies can be a sign of editing or re-saving.
    """
    # This analysis is only for JPEG files
    if image.format != 'JPEG':
        return "N/A (Not a JPEG)"
    
    try:
        # Pillow provides direct access to the Q-tables
        q_tables = image.quantization
        
        if not q_tables:
            return "No quantization tables found (unusual for JPEG)"

        # A simple check: most original photos have 1 or 2 tables (luma/chroma)
        num_tables = len(q_tables)
        if num_tables > 2:
            return f"Suspicious: Found {num_tables} quantization tables (expected 1-2)."
        
        # A more advanced analysis would compare these tables against a
        # database of known camera/software tables.
        
        return f"Standard: Found {num_tables} quantization tables."
        
    except Exception as e:
        return f"Error during Q-table analysis: {e}"


# --------------------------------------------
# 🖼️ HEADER
# --------------------------------------------
# Use st.markdown with inline HTML/CSS for a large, custom header
st.markdown(
    '<h1 style="font-size: 45px; font-weight: bold; text-align: center; color: #1F2937; text-shadow: 1px 1px 3px #ccc;">🔍 Digital Image Forensics Analyzer</h1>', 
    unsafe_allow_html=True
)
st.markdown(
    '<h3 style="text-align: center; font-size: 22px; color: #555;">Analyze metadata, detect hidden data, and expose manipulation 🧠</h3>', 
    unsafe_allow_html=True
)
st.divider()

# --------------------------------------------
# ⚙️ SESSION STATE SETUP
# --------------------------------------------
# Use Streamlit's session state to keep a running log of analyzed files
if "log_data" not in st.session_state:
    st.session_state.log_data = []

# --------------------------------------------
# 📁 FILE UPLOAD WIDGET
# --------------------------------------------
# Display the custom uploader header
st.markdown('<p class="uploader-header">📸 Upload an Image for Analysis</p>', unsafe_allow_html=True)
# The file uploader widget
uploaded_file = st.file_uploader(
    "Upload an image for analysis", 
    type=["jpg", "jpeg", "png"],  # Allowed file types
    label_visibility="collapsed"  # Hide the default label to use our custom one
)

# --------------------------------------------
# 📊 MAIN ANALYSIS LOGIC
# --------------------------------------------
# This block only runs if a file has been successfully uploaded
if uploaded_file:
    
    # --- 1. INITIAL FILE PROCESSING ---
    # Open the uploaded file as a PIL Image object
    image = Image.open(uploaded_file)
    # Get the file extension
    file_type = uploaded_file.type.split("/")[-1].upper()
    # Get the image format as detected by Pillow
    image_format = image.format if image.format else "Unknown"
    # Read the entire file into memory as bytes (needed for hashing and analysis)
    file_bytes = uploaded_file.getvalue()
    
    
    # --- 2. PERFORM ALL FORENSIC ANALYSES ---
    
    # Hashing: Calculate MD5 and SHA256 for file integrity
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # EXIF Metadata: Extract raw EXIF data
    exif_data_raw = {}
    if hasattr(image, "_getexif") and image._getexif() is not None:
        for tag, value in image._getexif().items():
            decoded = ExifTags.TAGS.get(tag, tag)  # Get human-readable tag name
            exif_data_raw[decoded] = value
            
    # Create a "clean" version of EXIF for display (decode bytes, handle GPS)
    exif_data_display = {}
    for tag, value in exif_data_raw.items():
        if isinstance(value, bytes):
            try:
                exif_data_display[tag] = value.decode('utf-8').strip('\x00')
            except UnicodeDecodeError:
                exif_data_display[tag] = str(value)  # Show as string if not decodable
        elif tag == 'GPSInfo':
             exif_data_display[tag] = "See GPS Map Analysis"
        else:
             exif_data_display[tag] = value

    # Hidden Data (Steganography): Check for data after End-of-File (EOF) marker
    hidden_data = None
    if file_type in ["JPEG", "JPG"]:
        eoi_index = file_bytes.rfind(b"\xff\xd9")  # Find last JPEG EOF marker
        if eoi_index != -1 and eoi_index + 2 < len(file_bytes):
            hidden_data = file_bytes[eoi_index + 2:]  # Get all bytes after it
    elif file_type == "PNG":
        iend_index = file_bytes.rfind(b"IEND")  # Find last PNG IEND chunk
        if iend_index != -1 and iend_index + 8 < len(file_bytes):
            hidden_data = file_bytes[iend_index + 8:]
    
    # Calculate size and entropy of the hidden data (if any)
    hidden_data_bytes = len(hidden_data) if hidden_data else 0
    hidden_data_entropy = calculate_entropy(hidden_data) if hidden_data else 0.0

    # ELA Analysis: Run the ELA function
    ela_image = perform_ela(image)
    
    # String Extraction: Run the strings function
    all_strings = extract_strings(file_bytes)
    
    # EXIF Thumbnail: Run the thumbnail extractor
    exif_thumbnail = get_exif_thumbnail(exif_data_raw)
    
    # GPS Data: Run the GPS converter
    gps_lat, gps_lon = None, None
    if 'GPSInfo' in exif_data_raw:
        gps_lat, gps_lon = convert_gps_to_decimal(exif_data_raw['GPSInfo'])

    # File Signature Check: Run the signature verifier
    signature_check_result = verify_file_signature(file_bytes, file_type)

    # Quantization Table Analysis: Run the Q-table analyzer
    q_table_analysis_result = analyze_quantization_tables(image)


    # --- 3. DISPLAY LAYOUT ---
    
    # Create a 2-column layout: 1 part for image, 2 parts for analysis
    col1, col2 = st.columns([1, 2])
    
    # Column 1: Display the uploaded image and the report download button
    with col1:
        st.image(image, caption=f"Uploaded Image ({image_format})", use_container_width=True)
        
        st.markdown("### 💾 Export Full Report")
        
        # --- Build the comprehensive text report ---
        report_text = f"""
Digital Image Forensics Report
==============================
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Case Details
----------------
Filename: {uploaded_file.name}
File Type: {file_type}
File Size: {len(file_bytes)} bytes
Image Mode: {image.mode}
Image Dimensions: {image.width} x {image.height}

Key Findings
----------------
EXIF Tags Found: {len(exif_data_display)}
GPS Location Found: {"Yes" if gps_lat else "No"}
Hidden Data Bytes: {hidden_data_bytes}
Hidden Data Entropy: {hidden_data_entropy:.4f} bits/byte
File Signature Check: {signature_check_result}
Quantization Tables: {q_table_analysis_result}

File Integrity (Hashes)
-----------------------
MD5: {md5_hash}
SHA256: {sha256_hash}

EXIF Metadata
----------------
"""
        if exif_data_display:
            # Convert the EXIF dict to a DataFrame for clean string formatting
            df = pd.DataFrame(list(exif_data_display.items()), columns=["Tag", "Value"])
            report_text += df.to_string()
        else:
            report_text += "No EXIF metadata found."

        # Add other analysis results to the report
        if gps_lat and gps_lon:
            report_text += f"\n\nGPS Coordinates: Lat {gps_lat:.6f}, Lon {gps_lon:.6f}"
        if exif_thumbnail:
            report_text += "\n\nEmbedded EXIF Thumbnail found."

        report_text += "\n\nHidden Data Analysis\n----------------\n"
        if hidden_data:
            report_text += f"WARNING: Found {hidden_data_bytes} bytes of data after image end marker.\n"
            report_text += f"Entropy: {hidden_data_entropy:.4f} bits/byte.\n"
            report_text += "Data Sample (first 64 bytes):\n"
            report_text += hidden_data[:64].hex(" ") # Show hex preview
        else:
            report_text += "No hidden data detected after image end marker."

        report_text += "\n\nString Analysis\n----------------\n"
        report_text += f"Found {len(all_strings)} readable strings (min 8 chars).\n\n"
        report_text += "\n".join(all_strings[:50]) # Add top 50 strings
        if len(all_strings) > 50:
            report_text += f"\n...and {len(all_strings) - 50} more."

        report_text += "\n\nELA Note:\n---------\nError Level Analysis was performed. Result not quantifiable in text report, refer to UI."
        report_text += f"\n\nQuantization Table Analysis:\n----------------------------\n{q_table_analysis_result}"
        # --- End of report build ---

        # Add the download button for the report
        st.download_button("📄 Download Full Report (TXT)", 
                             report_text, 
                             file_name=f"full_forensic_report_{uploaded_file.name}.txt")

    # Column 2: Display all analysis results in a tabbed interface
    with col2:
        tab_summary, tab_exif, tab_hidden, tab_ela, tab_strings = st.tabs([
            "📊 Summary", 
            "📋 EXIF Metadata", 
            "🧩 Hidden Data", 
            "🎨 ELA", 
            "📜 Strings"
        ])

        # --- TAB 1: SUMMARY (Dashboard) ---
        with tab_summary:
            st.markdown("### 📈 Key Findings Dashboard")
            
            # Use columns for a clean metric layout
            met_col1, met_col2, met_col3 = st.columns(3)
            met_col1.metric("EXIF Tags Found", f"{len(exif_data_display)}")
            met_col2.metric("Hidden Data", f"{hidden_data_bytes} bytes")
            met_col3.metric("Data Entropy", f"{hidden_data_entropy:.4f}")
            
            st.markdown("### 🧾 File Details")
            st.write(f"**Filename:** {uploaded_file.name}")
            st.write(f"**Detected File Type:** {file_type} ({image_format})")
            st.write(f"**File Size:** {len(file_bytes)} bytes")
            st.write(f"**Image Mode:** {image.mode}")
            st.write(f"**Image Dimensions:** {image.width} x {image.height} pixels")
            
            st.markdown("### 🛡️ File Signature Verification")
            if signature_check_result == "Pass":
                st.success(f"**PASS:** File signature matches its extension (`{file_type}`).")
            elif signature_check_result == "Fail":
                st.error(f"**FAIL!** File signature does NOT match its extension (`{file_type}`). The file may be misnamed or malicious.")
            else: # "Not_Checked"
                st.info(f"File type (`{file_type}`) not checked for signature.")

            st.markdown("### 📊 JPEG Quantization Table Analysis")
            if "N/A" in q_table_analysis_result:
                st.info(q_table_analysis_result)
            elif "Suspicious" in q_table_analysis_result:
                st.warning(q_table_analysis_result + " This may indicate re-compression or editing.")
            else: # "Standard"
                st.success(q_table_analysis_result + " (Appears typical for a JPEG).")
            st.caption("Quantization tables define JPEG compression. Inconsistencies can signal tampering.")

            st.markdown("### 🔒 File Integrity (Hashes)")
            st.code(f"MD5: {md5_hash}\nSHA-256: {sha256_hash}")
            st.caption("Hashes verify file integrity.")

        # --- TAB 2: EXIF METADATA ---
        with tab_exif:
            st.markdown("### 📍 GPS Geolocation")
            if gps_lat and gps_lon:
                st.success(f"**Location Found!** Lat: `{gps_lat:.6f}`, Lon: `{gps_lon:.6f}`")
                map_data = pd.DataFrame({'lat': [gps_lat], 'lon': [gps_lon]})
                st.map(map_data, zoom=12)
            else:
                st.info("ℹ️ No valid GPS coordinates found in EXIF data.")
            
            st.markdown("### 🕵️‍♂️ Embedded EXIF Thumbnail")
            if exif_thumbnail:
                st.image(exif_thumbnail, caption="Extracted Thumbnail")
                st.warning("**Forensic Note:** This thumbnail may differ from the main image, potentially revealing the original photo.")
            else:
                st.info("ℹ️ No embedded EXIF thumbnail was found.")
                
            st.markdown(f"### 🗂️ All EXIF Tags ({len(exif_data_display)} Found)")
            if not exif_data_display:
                st.info("ℹ️ No EXIF metadata found.")
            else:
                df_exif = pd.DataFrame(list(exif_data_display.items()), columns=["Tag", "Value"])
                
                # --- THIS IS THE FIX ---
                # Force the 'Value' column to be string type to prevent mixed-type error
                df_exif['Value'] = df_exif['Value'].astype(str)
                
                st.dataframe(df_exif, use_container_width=True, height=400)

        # --- TAB 3: HIDDEN DATA ---
        with tab_hidden:
            st.markdown("### 🧩 Hidden Data / Steganography")
            if hidden_data:
                st.warning(f"⚠️ **Hidden data detected after image end marker!**")
                st.markdown(f"- **Bytes Found:** `{hidden_data_bytes}`")
                st.markdown(f"- **Entropy:** `{hidden_data_entropy:.4f}` bits/byte")
                st.caption("A high entropy (e.g., > 7.5) suggests encrypted or compressed data.")
                st.markdown("##### Data Sample (first 64 bytes):")
                st.code(hidden_data[:64].hex(" ")) # Show hex dump
                # Allow user to download the hidden data for further analysis
                st.download_button("⬇️ Download Extracted Hidden Data (.bin)", 
                                     data=hidden_data, 
                                     file_name="hidden_data_dump.bin")
            else:
                st.success("✅ No hidden data detected after image end marker.")
            
            with st.expander("ℹ️ How is this detected?"):
                st.markdown("This checks for extra data appended *after* the standard End of File (EOF) marker.")

        # --- TAB 4: ERROR LEVEL ANALYSIS (ELA) ---
        with tab_ela:
            st.markdown("### 🎨 Error Level Analysis (ELA)")
            if ela_image:
                st.image(ela_image, caption="ELA Result", use_container_width=True)
                with st.expander("ℹ️ How to Read This ELA Image", expanded=True):
                    st.markdown("""
                    **ELA** highlights differences in the JPEG compression rate.
                    - **Original Areas:** Appear **dark or grey**.
                    - **Edited/Pasted Areas:** Will have a different compression history and appear **significantly brighter**.
                    """)
            else:
                st.error("Could not perform ELA. Image might not be a compatible JPEG/PNG format.")

        # --- TAB 5: STRING EXTRACTION ---
        with tab_strings:
            st.markdown(f"### 📜 Extracted Readable Strings")
            st.info(f"Found **{len(all_strings)}** readable strings (min 8 characters).")
            
            if all_strings:
                # Display all strings in a scrollable text box
                strings_display = "\n".join(all_strings)
                st.text_area("Found Strings:", strings_display, height=500, disabled=True)
            else:
                st.warning("No readable strings of 8+ characters were found.")
            
            with st.expander("ℹ️ What are 'Strings'?"):
                st.markdown("This scans the file's binary code for human-readable text, which can reveal software history, camera models, or hidden messages.")

    # --- 4. LOGGING ---
    # Append the results of this analysis to the session state log
    st.session_state.log_data.append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Filename": uploaded_file.name,
        "File Type": file_type,
        "Signature": signature_check_result,
        "Q_Table_Analysis": q_table_analysis_result,
        "MD5": md5_hash,
        "SHA256": sha256_hash,
        "EXIF Tags": len(exif_data_display),
        "GPS Found": "Yes" if gps_lat else "No",
        "Hidden Bytes": hidden_data_bytes,
        "Entropy": f"{hidden_data_entropy:.4f}"
    })


# --------------------------------------------
# 📊 SESSION LOG DISPLAY
# --------------------------------------------
# If the log has data, display it at the bottom of the page
if st.session_state.log_data:
    st.divider()
    st.subheader("🧾 Session Analysis Log")
    log_df = pd.DataFrame(st.session_state.log_data)
    
    # Re-order columns for a more logical layout
    log_columns = [
        "Timestamp", "Filename", "File Type", "Signature", "Q_Table_Analysis", "MD5", "SHA256", 
        "EXIF Tags", "GPS Found", "Hidden Bytes", "Entropy"
    ]
    # Filter for columns that actually exist (in case one fails)
    log_df = log_df[[col for col in log_columns if col in log_df.columns]]
    st.dataframe(log_df, use_container_width=True)

    # --- CSV Download for Log ---
    csv_buffer = io.StringIO()
    log_df.to_csv(csv_buffer, index=False)
    st.download_button("⬇️ Download Session Log (CSV)", data=csv_buffer.getvalue(),
                         file_name="forensic_log.csv", mime="text/csv")

# --------------------------------------------
# ⚙️ FOOTER
# --------------------------------------------
st.divider()
# Add a custom footer for the project
st.markdown(
    """
    <div style='text-align:center; color:#888;'>
        <small>Developed for <b>Cyber Forensics & Investigation Project</b></small>
    </div>
    """,
    unsafe_allow_html=True
)