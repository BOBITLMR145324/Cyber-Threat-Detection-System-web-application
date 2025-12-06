🛡️ Cyber Threat Detection System (CTDS)

A secure, database-driven web platform designed to help organizations detect, record, visualize, and analyze cyber threats.
CTDS integrates modern web technologies, robust backend logic, and a secure SQL Server database to provide a centralized 
threat-monitoring solution for cybersecurity analysts, IT administrators, and security teams.

**Key Features**
** Secure User Authentication**

Encrypted password storage (SHA-256)

Session management with secure cookies

Role-Based Access Control (Admin / Standard User)

** Threat Logging Interface**

Log incidents with:

Threat type (e.g., Malware, Phishing, DDoS)

Severity (Low, Medium, High, Critical)

Description & timestamps

Optional metadata (e.g., source IP)

Consistent structure for accurate incident tracking

** Interactive Dashboards**

Powered by Chart.js and Flask:

Threat distribution by severity

Threat distribution by type

Recent activity feeds

Real-time summary statistics

** Filtering & Search Tools**

Filter incidents by date, severity, or threat type

Keyword search for rapid investigations

Paginated tables for large datasets

 **Admin Tools**

User account creation & management

Oversight of all logged threats

System governance and monitoring

**Secure and Scalable Database
**
SQL Server backend

Parameterized queries via pyodbc

Normalized schema with enforced data integrity

Indexing optimized for analytics queries

** System Architecture**

CTDS follows a three-tier architecture:

1. Presentation Layer (Frontend)

Built with:

HTML5, CSS3, Bootstrap

JavaScript & Chart.js

Jinja2 templating

Provides:

Login/registration forms

Threat submission interfaces

Responsive dashboards

Threat history tables

2. Application Layer (Backend – Flask)

Handles:

Authentication & access control

Threat logging and validation

Analytics computation

Secure routing and data processing

API-style JSON responses for charts

Modules:

Authentication Module

Threat Logging Module

Dashboard Analytics Module

Error Handling

3. Data Layer (SQL Server Database)

Core tables:

Users – account & role management

ThreatRecords – primary incident repository

**Features:**

Enforced foreign keys

Secured access policies

Support for future extensions (AI, SIEM, alerts)

** Security Architecture**

CTDS uses a multi-layer, defense-in-depth approach:

Authentication Security

Hashed credentials

Secure session tokens

Fail-safe authentication checks

Input Validation

Prevents:

SQL Injection (via parameterized queries)

XSS

CSRF

Brute force attempts

 Database Security

RBAC-aligned permissions

Controlled query execution

Secure audit trails (optional future module)

 Network & Communication Security

Supports HTTPS/TLS

Firewall and port hardening recommended

 Testing Strategy

CTDS uses a comprehensive testing methodology:

 Unit Testing

Authentication logic

Hashing functions

SQL execution wrappers

Input sanitization

 Integration Testing

Form submission → backend → database

Dashboard → API → JSON dataset

 System Testing

End-to-end workflows: login → log threat → visualize

 User Acceptance Testing (UAT)

Performed with:

Cyber analysts

IT administrators

Non-technical staff

Security Testing

Password hashing verification

RBAC violation attempts

SQL injection/XSS simulations

Performance & Load Testing

Dashboard responsiveness

Query performance under load

Installation & Deployment Guide
1. Prerequisites

Python 3.8+

SQL Server (local or remote)

PyODBC driver installed

pip package manager

2. Install Dependencies
pip install -r requirements.txt

3. Configure Environment Variables

Create a .env file in the project root:

DB_SERVER=your_sql_server
DB_NAME=your_database_name
SECRET_KEY=your_session_secret
TRUSTED_CONNECTION=yes

4. Set Up Database

Run the SQL schema scripts (located in the /database/ folder, if included):

CREATE TABLE Users (...);
CREATE TABLE ThreatRecords (...);

5. Launch the Application
python Ctds_app.py


Project Structure
CTDS/
│── Ctds_app.py
│── static/
│── templates/
│── database/
│── requirements.txt
│── README.md
│── .env (not included in repo)

Future Enhancements

The system is built to scale into advanced cyber-intelligence capabilities:

Machine Learning–based anomaly detection

Real-time threat alerts (email/SMS)

Integration with SIEM platforms

Extended audit logging

Threat scoring models

Multi-tenant organization dashboards

Conclusion

CTDS is a robust, secure, and scalable cyber-monitoring platform that empowers organizations to:

Detect threats faster

Analyze threat patterns visually

Improve decision-making

Strengthen cybersecurity posture

Its modular design ensures high maintainability, reliable performance, and compatibility with future threat intelligence innovations.
