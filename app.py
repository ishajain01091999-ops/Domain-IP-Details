import streamlit as st
import whois
import pytz
from datetime import datetime
import pandas as pd
import requests
import socket
from urllib.parse import urlparse

# -----------------------------------
# API KEYS
# -----------------------------------
WHOIS_API_KEY = "YOUR_WHOISXML_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"


# -----------------------------------
# FOLLOW REDIRECT URL
# -----------------------------------
def get_final_url(domain_name):
    try:
        response = requests.get(domain_name, allow_redirects=True, timeout=10)
        return response.url
    except:
        return domain_name


# -----------------------------------
# EXTRACT DOMAIN
# -----------------------------------
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else parsed.path


# -----------------------------------
# WHOIS API CHECK
# -----------------------------------
def get_whois_api(domain):

    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"

        response = requests.get(url, timeout=10).json()

        record = response.get("WhoisRecord", {})

        registrar = record.get("registrarName", "N/A")
        creation_date = record.get("createdDate", "N/A")
        expiration_date = record.get("expiresDate", "N/A")

        return registrar, creation_date, expiration_date

    except:
        return None, None, None


# -----------------------------------
# LOCAL WHOIS FALLBACK
# -----------------------------------
def get_domain_details(domain_name):

    registrar, creation_date, expiration_date = get_whois_api(domain_name)

    if registrar and creation_date:
        return registrar, creation_date, expiration_date

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
            creation_date = "N/A"

        if expiration_date:
            expiration_date = expiration_date.astimezone(utc)
            expiration_date = expiration_date.strftime('%a, %d %b %Y %H:%M:%S') + " GMT"
        else:
            expiration_date = "N/A"

        return registrar, creation_date, expiration_date

    except:
        return "N/A", "N/A", "N/A"


# -----------------------------------
# CALCULATE DOMAIN AGE + EXPIRY
# -----------------------------------
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

        domain_age_years = round(active_days / 365, 2)

        return active_days, expiry_days, domain_age_years

    except:
        return "N/A", "N/A", "N/A"


# -----------------------------------
# GET IP ADDRESS
# -----------------------------------
def get_ip(domain):

    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return "N/A"


# -----------------------------------
# GET IP LOCATION
# -----------------------------------
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


# -----------------------------------
# CHECK BLACKLIST
# -----------------------------------
def check_ip_blacklist(ip):

    try:

        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        response = requests.get(url, headers=headers, params=params)

        data = response.json()["data"]

        abuse_score = data.get("abuseConfidenceScore", 0)

        if abuse_score > 0:
            status = "Blacklisted / Suspicious"
        else:
            status = "Clean"

        return status, abuse_score

    except:
        return "Unknown", "N/A"


# -----------------------------------
# STREAMLIT UI
# -----------------------------------
st.set_page_config(page_title="Domain Intelligence Dashboard", layout="wide")

st.title("🌐 Domain Intelligence Dashboard")

st.write("Fetch WHOIS, Domain Age, IP Address, IP Location and Blacklist details")

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

        active_days, expiry_days, domain_age_years = calculate_days(
            creation_date, expiration_date
        )

        ip = get_ip(domain)

        country, city, isp = get_ip_location(ip)

        blacklist_status, abuse_score = check_ip_blacklist(ip)

        results.append({

            "Input URL": url,
            "Final URL": final_url,
            "Domain": domain,
            "Registrar": registrar,
            "Creation Date": creation_date,
            "Expiration Date": expiration_date,
            "Domain Age (Years)": domain_age_years,
            "Active Days": active_days,
            "Expiry Days": expiry_days,
            "IP Address": ip,
            "Country": country,
            "City": city,
            "ISP": isp,
            "Blacklist Status": blacklist_status,
            "Abuse Score": abuse_score

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
