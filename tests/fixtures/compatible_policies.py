"""
Policy fixtures compatible with current parser format.
Based on realistic scenarios but using the expected structure.
"""

# Healthcare policy in compatible format
# Note: Using simple conditions to avoid false positive command injection detection from &&
HEALTHCARE_COMPATIBLE = {
    "name": "Healthcare HIPAA Policy",
    "template_id": "healthcare-hipaa",
    "mask": [
        "patientInformation.demographics.ssn",
        "patientInformation.demographics.dateOfBirth",
        "patientInformation.medicalRecordNumber",
        "medicalHistory",
        "currentMedications",
        "laboratoryResults",
        "insuranceInformation.policyNumber",
        "allergiesAndAdverseReactions",
        "patientInformation.contactInformation.address",
        "assessmentAndPlan"
    ],
    "unmask_roles": ["admin", "doctor", "nurse"],
    "conditions": [
        "trustScore > 90",
        "role == 'doctor'",
        "role == 'nurse'",
        "role == 'pharmacist'"
    ]
}

# Financial policy in compatible format
# Note: Using simple conditions to avoid false positive command injection detection from &&
FINANCIAL_COMPATIBLE = {
    "name": "Financial PCI Policy",
    "template_id": "finance-pci",
    "mask": [
        "financialProfile.bankAccounts",
        "financialProfile.creditCards",
        "financialProfile.creditScore",
        "transactionHistory",
        "personalInformation.ssn",
        "employmentInformation.annualSalary"
    ],
    "unmask_roles": ["admin", "financial_advisor"],
    "conditions": [
        "trustScore > 95",
        "role == 'financial_advisor'",
        "role == 'loan_officer'",
        "role == 'account_owner'"
    ]
}

# HR policy in compatible format
HR_COMPATIBLE = {
    "name": "HR Employee Data Policy",
    "template_id": "hr-employee",
    "mask": [
        "personalInfo.ssn",
        "personalInfo.dateOfBirth",
        "compensation",
        "bankingInfo",
        "performanceReviews",
        "contactInformation.address"
    ],
    "unmask_roles": ["admin", "hr_admin", "hr_manager"],
    "conditions": [
        "trustScore > 85 && role == 'hr_admin'",
        "trustScore > 80 && role == 'manager' && direct_report == true",
        "trustScore > 75 && role == 'payroll' && processing_period == true",
        "role == 'employee_self'"
    ]
}

# Simple PII policy
PII_BASIC_COMPATIBLE = {
    "name": "Basic PII Protection",
    "template_id": "pii-basic",
    "mask": ["name", "email", "ssn", "phone", "address"],
    "unmask_roles": ["admin"],
    "conditions": [
        "trustScore > 80",
        "role == 'customer_service' && active_case == true",
        "role == 'account_owner'"
    ]
}

# Test-specific policies
TEST_POLICIES = {
    "minimal": {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": ["trustScore > 90"]
    },
    "nested_fields": {
        "mask": [
            "patient.demographics.ssn",
            "patient.contact.phone",
            "patient.medical.diagnosis"
        ],
        "unmask_roles": ["admin", "doctor"],
        "conditions": [
            "role == 'doctor' && patient_assigned == true",
            "trustScore > 85"
        ]
    },
    "complex_conditions": {
        "mask": ["salary", "bonus", "stock_options"],
        "unmask_roles": ["hr_admin", "cfo"],
        "conditions": [
            "role == 'manager' && direct_report == true && review_period == true",
            "role == 'hr_admin' && trustScore > 80",
            "(role == 'employee' && self_service == true) || role == 'admin'"
        ]
    }
}