EXECUTION CHECKLIST  IN ORDER
STEP 1: Baseline 

Register User A

Login → save token

Create 1–2 books

Screenshot normal behavior

STEP 2:Authorization Testing (CORE)

BOLA: access another user’s book

BOPLA: modify protected fields

BFLA: attempt restricted actions

STEP 3: IDOR

Manipulate book_id

Test predictability / enumeration

STEP 4: Business Logic

Abuse create/update/delete flows

Repeat actions

Skip expected steps

STEP 5: Inventory & Misconfig

Analyze /db-init

Check exposure & protection

STEP 6: Document Findings

One vuln at a time

Clear impact

Clear fix
