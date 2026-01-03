VAmPI API Security VAPT

OWASP API Top 10–Aligned Assessment

 Overview

This repository documents a professional Vulnerability Assessment & Penetration Testing (VAPT) conducted against VAmPI (Vulnerable API), an intentionally vulnerable REST API designed to demonstrate common API security weaknesses.

The assessment follows a methodology-driven approach, focusing on authorization, authentication, object ownership, business logic flaws, and API design weaknesses, aligned with the OWASP API Security Top 10.

 Disclaimer
This assessment was performed against a local, intentionally vulnerable lab for educational and research purposes only.

 Objectives

Build a complete API inventory

Understand authentication & authorization models

Identify OWASP API Top 10 vulnerabilities

Demonstrate realistic API abuse scenarios

Produce clear, remediation-focused findings

 Scope
In-Scope

REST API endpoints exposed by VAmPI

Authentication & authorization mechanisms

Object-level access control

Business logic flows

Out-of-Scope

Infrastructure / OS-level testing

Denial of Service (DoS)

Brute-force attacks

🌐 Environment
Item	Value
Application	VAmPI (Vulnerable API)
Interface	Swagger / OpenAPI
Base URL	http://127.0.0.1:5000
API Spec	/openapi.json
Tester	Ibrahim Sheikh
Platform	Local Lab (Kali Linux)

 High-Level API Resources

The API exposes the following primary resources:

Resource	Description
home	API root / health endpoint
users	User registration, authentication, identity
books	Core object resource (CRUD operations)
db-init	Database initialization endpoint

These resources form the entire attack surface for this assessment.


 Authentication Model (Observed)

Token-based authentication (JWT)

Token supplied via Authorization header

Role/ownership checks appear inconsistent (to be validated)


 API Inventory 

This inventory defines what exists before testing what breaks.

Endpoint	Method	Auth Required	Object
/	GET	No	–
/users/register	POST	No	user
/users/login	POST	No	token
/users/me	GET	Yes	user
/books	GET	Yes	book
/books	POST	Yes	book
/books/{id}	GET	Yes	book_id
/books/{id}	PUT	Yes	book_id
/books/{id}	DELETE	Yes	book_id
/db-init	POST	No / Weak	database

 Inventory will be expanded as testing progresses.
 

👤 Baseline User Journey

To establish normal behavior, the following legitimate user flow is used as a baseline:

Register a new user

Authenticate and receive token

Perform allowed actions:

View own profile

Create a book

View/update/delete own book

All vulnerabilities are identified relative to this baseline.


 Methodology

The assessment follows the OWASP API Security Top 10 with emphasis on:

API1: Broken Object Level Authorization (BOLA)

API2: Broken Authentication

API3: Broken Object Property Level Authorization (BOPLA)

API5: Broken Function Level Authorization (BFLA)

API6: Unrestricted Access to Sensitive Business Flows

API9: Improper Inventory Management

Testing is performed in controlled stages, prioritizing authorization and logic flaws over injection-based issues.


Findings Structure

Each finding includes:

Description

Affected endpoint(s)

OWASP API category

Impact

Risk level

Remediation guidance


 Status

 Scope defined

 API inventory created

 Authorization testing

 Business logic testing

 Findings documentation

 Final report
 

🔚 Conclusion

This project demonstrates a real-world API VAPT workflow, emphasizing methodology, clarity, and security impact over ad-hoc exploitation.
