from fastapi import FastAPI, UploadFile, File
import hashlib
import yara
import requests
import os
import glob

app = FastAPI()

threat_db = {}
yara_rules = None

# Create local rules directory
os.makedirs("yara_files", exist_ok=True)

# Get GitHub PAT
github_token = os.getenv('github_token')

# Download threat DB and all YARA rules from GitHub
def download_threat_db():
    global threat_db, yara_rules

    # GitHub API headers with the token for authentication
    headers = {
        "Authorization": f"token {github_token}"
    }
    
    # Download malware hash database
    hash_url = "https://raw.githubusercontent.com/Kybero/Kybero-Control/main/hash/hash.txt"
    hashes_response = requests.get(hash_url, headers=headers)
    
    with open("hash.txt", "w") as file:
        file.write(hashes_response.text)
    
    # Parse hash database
    with open("hash.txt", "r") as file:
        for line in file:
            if '...' in line:
                name, hash_value = line.strip().split(' ... ')
                threat_db[hash_value] = name
    
    # Download all YARA rule files in the GitHub folder
    folder_url = "https://api.github.com/repos/Kybero/Kybero-Control/contents/yara"
    response = requests.get(folder_url, headers=headers)
    
    if response.status_code == 200:
        try:
            files = response.json()  # Decode the response as JSON
            for file_info in files:
                if isinstance(file_info, dict) and file_info.get("name", "").endswith(".yar"):
                    download_url = file_info["download_url"]
                    file_path = os.path.join("yara_files", file_info["name"])
                    
                    yara_response = requests.get(download_url, headers=headers)
                    if yara_response.status_code == 200:
                        with open(file_path, "w") as file:
                            file.write(yara_response.text)
                    else:
                        print(f"Failed to download {file_info['name']} with status code {yara_response.status_code}")
        except ValueError:
            print("Error parsing the JSON response from GitHub API.")
    else:
        print("Failed to retrieve the file list from GitHub API:", response.text)
    
    # Compile all YARA rule files (including subdirectories)
    rule_files = glob.glob("yara_files/**/*.yar", recursive=True)
    yara_rules = yara.compile(filepaths={f"rule_{i}": path for i, path in enumerate(rule_files)})

# Run download when starting
download_threat_db()

# File scanning endpoint
@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    contents = await file.read()
    file_hash = hashlib.sha256(contents).hexdigest()

    # SHA256 hash detection
    if file_hash in threat_db:
        return {
            "file_name": file.filename,
            "threat_detected": True,
            "detection_method": "SHA256",
            "threat_name": threat_db[file_hash]
        }

    # YARA rule detection
    yara_matches = yara_rules.match(data=contents)
    if yara_matches:
        threat_meta = yara_matches[0].meta.get("threat_name", "UnknownMalware")  # Extract threat_name from meta
        return {
            "file_name": file.filename,
            "threat_detected": True,
            "detection_method": "YARA",
            "threat_name": threat_meta
        }

    return {
        "file_name": file.filename,
        "threat_detected": False
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
