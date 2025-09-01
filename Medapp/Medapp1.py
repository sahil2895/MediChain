import os
import json
import requests
import streamlit as st
from cryptography.fernet import Fernet


# Hide Streamlit's default menu, footer, and GitHub button
hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    [data-testid="stToolbar"] {visibility: hidden !important;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)


# Load Secrets from Streamlit
PINATA_WRITE_KEY = st.secrets["PINATA_WRITE_KEY"]
PINATA_WRITE_SECRET = st.secrets["PINATA_WRITE_SECRET"]
PINATA_READ_KEY = st.secrets["PINATA_READ_KEY"]
PINATA_READ_SECRET = st.secrets["PINATA_READ_SECRET"]


# User Data JSON
USER_DATA_FILE = "users.json"

def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f, indent=4)

users = load_users()


# Pinata Functions
def upload_to_pinata(file_path):
    """Upload encrypted PDF to Pinata (Write Key)."""
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": PINATA_WRITE_KEY,
        "pinata_secret_api_key": PINATA_WRITE_SECRET,
    }
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()["IpfsHash"]
    else:
        raise Exception(f"Pinata upload failed: {response.text}")

def download_from_pinata(cid, output_path):
    """Download file from Pinata gateway (Read Key)."""
    url = f"https://gateway.pinata.cloud/ipfs/{cid}"
    headers = {
        "pinata_api_key": PINATA_READ_KEY,
        "pinata_secret_api_key": PINATA_READ_SECRET,
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        with open(output_path, "wb") as f:
            f.write(response.content)
        return output_path
    else:
        raise Exception(f"Pinata download failed: {response.text}")


# Encryption Helpers
def encrypt_pdf(file, key):
    fernet = Fernet(key)
    data = file.read()
    encrypted = fernet.encrypt(data)
    enc_file = "encrypted_report.pdf"
    with open(enc_file, "wb") as f:
        f.write(encrypted)
    return enc_file

def decrypt_pdf(enc_file, key):
    fernet = Fernet(key)
    with open(enc_file, "rb") as f:
        encrypted_data = f.read()
    decrypted = fernet.decrypt(encrypted_data)
    dec_file = "decrypted_report.pdf"
    with open(dec_file, "wb") as f:
        f.write(decrypted)
    return dec_file


# Streamlit 
st.title("🏥 Multi-User Hospital Report DApp (Pinata + Encryption)")

menu = ["Register User", "Upload Report", "View Reports"]
choice = st.sidebar.selectbox("Menu", menu)


# Register User
if choice == "Register User":
    st.subheader("🧑 Register User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["Patient", "Doctor"])

    if st.button("Register"):
        if username in users:
            st.warning("⚠️ User already exists!")
        else:
            users[username] = {"password": password, "role": role, "reports": []}
            save_users(users)
            st.success(f"✅ {role} '{username}' registered successfully!")


# Upload Reports
elif choice == "Upload Report":
    st.subheader("📤 Upload Report")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    pdf_file = st.file_uploader("Choose Report (PDF)", type=["pdf"])

    if st.button("Upload Report"):
        if username not in users:
            st.error("❌ User not found")
        elif users[username]["password"] != password:
            st.error("❌ Invalid password")
        elif pdf_file is None:
            st.warning("⚠️ Please upload a PDF")
        else:
            try:
                # Generate encryption key for this report
                key = Fernet.generate_key()
                st.info(f"🔑 Save this decryption key securely: `{key.decode()}`")

                # Encrypt PDF
                enc_file = encrypt_pdf(pdf_file, key)

                # Upload encrypted PDF to Pinata
                cid = upload_to_pinata(enc_file)

                # Store CID in user record
                users[username]["reports"].append(cid)
                save_users(users)

                st.success(f"✅ Report uploaded! CID: {cid}")

                # Clean up local encrypted file
                os.remove(enc_file)

            except Exception as e:
                st.error(f"❌ Upload failed: {e}")

# View Reports
elif choice == "View Reports":
    st.subheader("📥 View Reports")
    username = st.text_input("Username", key="view_user")
    password = st.text_input("Password", type="password", key="view_pass")

    if username and password:
        if username not in users:
            st.error("❌ User not found")
        elif users[username]["password"] != password:
            st.error("❌ Invalid password")
        else:
            reports = users[username]["reports"]
            if len(reports) == 0:
                st.warning("⚠️ No reports found.")
            else:
                for idx, cid in enumerate(reports):
                    st.write(f"📄 Report {idx+1}: CID {cid}")

                    # Store keys in session_state to avoid dynamic input issues
                    if f"key_{idx}" not in st.session_state:
                        st.session_state[f"key_{idx}"] = ""

                    st.session_state[f"key_{idx}"] = st.text_input(
                        f"Enter decryption key for Report {idx+1}",
                        type="password",
                        key=f"input_key_{idx}"
                    )

                    # Download button for each report
                    if st.button(f"Decrypt & Download Report {idx+1}", key=f"btn_{idx}"):
                        try:
                            # Download encrypted file from Pinata
                            url = f"https://gateway.pinata.cloud/ipfs/{cid}"
                            headers = {
                                "pinata_api_key": PINATA_READ_KEY,
                                "pinata_secret_api_key": PINATA_READ_SECRET,
                            }
                            response = requests.get(url, headers=headers)
                            if response.status_code != 200:
                                raise Exception(f"Pinata download failed: {response.text}")

                            encrypted_data = response.content

                            # Decrypt in memory using provided key
                            fernet = Fernet(st.session_state[f"key_{idx}"].encode())
                            decrypted_data = fernet.decrypt(encrypted_data)

                            # Download directly from memory
                            st.download_button(
                                label=f"⬇️ Download Decrypted Report {idx+1}",
                                data=decrypted_data,
                                file_name=f"report_{idx+1}.pdf",
                                mime="application/pdf"
                            )
                            st.success("✅ Decryption successful!")

                        except Exception as e:
                            st.error(f"❌ Decryption failed: {e}")
