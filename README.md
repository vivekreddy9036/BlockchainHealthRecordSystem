#MedSecureChain: Health Record Management on Hyperledger Fabric
Overview

MedSecureChain is a decentralized health record management system built on Hyperledger Fabric. It allows for secure and transparent management of health data, including granting and revoking access to healthcare providers, storing audit logs, and ensuring privacy through encryption. This chaincode implementation ensures that patient data is managed efficiently with the option for patients to control access and provide consent to healthcare professionals.
Key Features

    Decentralized Health Record Management: Health records are stored on a blockchain to ensure immutability and transparency.
    Data Encryption: Sensitive data, such as the IPFS hash of health records, is encrypted using SHA-256 before storage.
    Access Control: Patients can grant or revoke access to their health records to specific doctors with a multi-signature approach.
    Audit Logs: Every action on a health record (e.g., access granted, access revoked) is logged for transparency and compliance.
    Version Control: Each health record has versioning to track changes over time.

Contract Overview

The chaincode consists of the following components:
1. HealthRecord

This struct holds the main health record information, including:

    ID: Unique identifier for the health record.
    IPFSHash: Encrypted IPFS hash representing the health record's data.
    Patient: The patient to whom the health record belongs.
    Doctor: The doctor who has access to the record (if access is granted).
    AccessGranted: Whether access is granted to the doctor.
    Version: Version of the health record.
    AccessExpiration: Expiration time for the doctor's access to the record.
    Timestamp: The time when the record was created or last updated.
    Source: Source of the health record (e.g., hospital, clinic).
    Verified: Whether the health record is verified.
    Consent: Consent from doctors for accessing the health record.
    Status: The health status of the patient (e.g., "Critical", "Stable").
    AuditLogs: A list of audit log entries documenting who accessed the record and when.

2. AuditLog

Each record has an associated list of audit logs to track all actions related to the record, including:

    UserID: The user who performed the action.
    Action: The action taken (e.g., "Grant Access", "Revoke Access").
    Timestamp: The time when the action occurred.
    Comment: An optional comment describing the action.

3. Functions

    AddHealthRecord: Adds a new health record to the blockchain.
    GrantAccess: Grants access to a doctor, requiring consent from both the patient and the doctor.
    RevokeAccess: Revokes access from a doctor, removing their consent.
    encryptData: Encrypts sensitive data (like the IPFS hash) using SHA-256 for privacy.

Key Functions Explained
AddHealthRecord

This function allows the patient to add a health record to the blockchain. The record includes details like the patient's identity, the health status, and a hash of the IPFS file containing the health data. The hash is encrypted for privacy.
GrantAccess

This function allows a patient to grant access to their health record to a doctor. Both the patient and the doctor must consent for access to be granted. The transaction is logged in the blockchain's audit logs.
RevokeAccess

This function allows a patient to revoke access from a doctor. It removes the doctor's consent from the health record and logs the action in the audit logs.
Logging

This chaincode uses the logrus library for enhanced logging. Every important action (e.g., adding a health record, granting/revoking access) is logged with details such as the user performing the action, the health record ID, and any errors encountered during the process.
Usage

To use this chaincode, ensure that you have a running Hyperledger Fabric network and the necessary dependencies installed. This chaincode interacts with Hyperledger Fabric's ledger to store and manage health records.
Deployment Instructions

    Install Dependencies: Ensure that you have Go and Hyperledger Fabric's chaincode environment set up.

    Deploy the Chaincode:
        Deploy the MedSecureChain chaincode onto your Hyperledger Fabric network.
        Initialize and instantiate the chaincode on the appropriate channel.

    Invoke Transactions: Use Fabric's CLI or a custom application to interact with the chaincode and invoke transactions such as adding health records, granting/revoking access, and retrieving records.

Security Considerations

    Data Encryption: The IPFS hash is encrypted before being stored on the blockchain, ensuring that sensitive health data remains private.
    Access Control: Only the patient can grant or revoke access, ensuring that the control over who can view the health data is in the hands of the patient.
    Audit Logs: Every action is logged, allowing for traceability and accountability in the handling of health records.

License

This project is licensed under the MIT License. See the LICENSE file for more details.
Contributing

Contributions to MedSecureChain are welcome! If you have suggestions or improvements, feel free to fork the repository and create a pull request.
Contact

For further inquiries, feel free to contact the development team at contact@medsecurechain.com.
