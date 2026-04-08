import streamlit as st
import whois
import pytz
from datetime import datetime
import pandas as pd
import requests
import socket
from urllib.parse import urlparse

# ------------------------------
# FOLLOW REDIRECT URL
# ------------------------------
def get_final_url(domain_name):
    try:
        response = requests.get(domain_name, allow_redirects=True, timeout=10)
        return response.url
    except:
        return domain_name


# ------------------------------
# EXTRACT DOMAIN
# ------------------------------
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else parsed.path


# ------------------------------
# GET WHOIS DETAILS
# ------------------------------
def get_domain_details(domain_name):

    try:
        domain_info = whois.whois(domain_name)

        creation_date = domain_info.get("creation_date")
        expiration_date = domain_info.get("expiration_date")
        registrar = domain_info.get("registrar", "N/A")

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        utc = pytz.UTC

        if creation_date:
            creation_date = creation_date.astimezone(utc)
            creation_date = creation_date.strftime('%a, %d %b %Y %H:%M:%S') + " GMT"
        else:
            creation_date = "No Data"

        if expiration_date:
            expiration_date = expiration_date.astimezone(utc)
            expiration_date = expiration_date.strftime('%a, %d %b %Y %H:%M:%S') + " GMT"
        else:
            expiration_date = "No Data"

        return registrar, creation_date, expiration_date

    except:
        return "N/A", "No Data", "No Data"


# ------------------------------
# CALCULATE DAYS
# ------------------------------
def calculate_days(creation_date, expiration_date):

    try:
        utc = pytz.UTC
        current_date = datetime.now(utc)

        creation_date = pd.to_datetime(
            creation_date.replace(" GMT", ""), errors="coerce"
        ).tz_localize(utc)

        expiration_date = pd.to_datetime(
            expiration_date.replace(" GMT", ""), errors="coerce"
        ).tz_localize(utc)

        active_days = (current_date - creation_date).days
        expiry_days = (expiration_date - current_date).days

        return active_days, expiry_days

    except:
        return "N/A", "N/A"


# ------------------------------
# DOMAIN AGE (RELATIVE FORMAT)
# ------------------------------
def calculate_domain_age(creation_date):

    try:
        if creation_date in ["No Data", "N/A", None]:
            return "No Data"

        creation_date = pd.to_datetime(
            creation_date.replace(" GMT", ""), errors="coerce"
        )

        today = datetime.utcnow()

        delta_days = (today - creation_date).days

        years = delta_days // 365
        months = delta_days // 30
        weeks = delta_days // 7

        if years >= 1:
            return f"{years} year ago" if years == 1 else f"{years} years ago"

        elif months >= 1:
            return f"{months} month ago" if months == 1 else f"{months} months ago"

        elif weeks >= 1:
            return f"{weeks} week ago" if weeks == 1 else f"{weeks} weeks ago"

        else:
            return f"{delta_days} days ago"

    except:
        return "No Data"


# ------------------------------
# GET IP ADDRESS
# ------------------------------
def get_ip(domain):

    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return "N/A"


# ------------------------------
# GET IP LOCATION
# ------------------------------
def get_ip_location(ip):

    try:
        url = f"http://ip-api.com/json/{ip}"
        res = requests.get(url).json()

        country = res.get("country", "N/A")
        city = res.get("city", "N/A")
        isp = res.get("isp", "N/A")

        return country, city, isp

    except:
        return "N/A", "N/A", "N/A"


# ------------------------------
# CHECK IP BLACKLIST
# ------------------------------
def check_blacklist(ip):

    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"

        headers = {
            "Key": "YOUR_ABUSEIPDB_API_KEY",
            "Accept": "application/json"
        }

        response = requests.get(url, headers=headers)

        data = response.json()["data"]

        score = data.get("abuseConfidenceScore", 0)

        if score > 0:
            return "Yes"
        else:
            return "No"

    except:
        return "Unknown"


# ------------------------------
# STREAMLIT UI
# ------------------------------
st.set_page_config(page_title="Domain Intelligence Dashboard", layout="wide")

st.title("🌐 Domain Intelligence Dashboard")

st.write("Fetch WHOIS, IP Address, IP Location and Domain Age details")

urls = st.text_area(
    "Enter Website URLs (one per line)",
    placeholder="https://example.com\nhttps://google.com"
)

if st.button("Analyze Domains"):

    results = []

    url_list = urls.split("\n")

    progress = st.progress(0)

    for i, url in enumerate(url_list):

        url = url.strip()

        if not url:
            continue

        final_url = get_final_url(url)

        domain = extract_domain(final_url)

        registrar, creation_date, expiration_date = get_domain_details(domain)

        active_days, expiry_days = calculate_days(creation_date, expiration_date)

        domain_age = calculate_domain_age(creation_date)

        ip = get_ip(domain)

        country, city, isp = get_ip_location(ip)

        blacklist_status = check_blacklist(ip)

        results.append({
            "Input URL": url,
            "Final URL": final_url,
            "Domain": domain,
            "Registrar": registrar,
            "Registration Date": creation_date,
            "Domain Age": domain_age,
            "Expiration Date": expiration_date,
            "Active Days": active_days,
            "Expiry Days": expiry_days,
            "IP Address": ip,
            "Country": country,
            "City": city,
            "ISP": isp,
            "blacklisted_ip_location_detected": blacklist_status
        })

        progress.progress((i + 1) / len(url_list))

    df = pd.DataFrame(results)

    st.success("Analysis Complete")

    st.dataframe(df, use_container_width=True)

    csv = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "Download CSV",
        csv,
        "domain_intelligence.csv",
        "text/csv"
    )
