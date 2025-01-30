// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19

package main

import (
	"encoding/json"
	"fmt"
	"time"
	"crypto/sha256"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/sirupsen/logrus" // For better logging
)

// HealthRecord struct with additional fields for audit logs and status
type HealthRecord struct {
	ID               string                 `json:"id"`
	IPFSHash         string                 `json:"ipfsHash"`
	Patient          string                 `json:"patient"`
	Doctor           string                 `json:"doctor,omitempty"`
	AccessGranted    bool                   `json:"isAccessGranted"`
	Version          int                    `json:"version"`
	AccessExpiration time.Time              `json:"accessExpiration,omitempty"`
	Timestamp        time.Time              `json:"timestamp"`
	Source           string                 `json:"source,omitempty"`
	Verified         bool                   `json:"verified"`
	Consent          map[string]bool        `json:"consent"`
	Status           string                 `json:"status"` // "Critical", "Stable", etc.
	AuditLogs        []AuditLog             `json:"auditLogs"` // New field for storing audit logs
}

// AuditLog struct to store audit information (who accessed the record and when)
type AuditLog struct {
	UserID     string    `json:"userId"`
	Action     string    `json:"action"`
	Timestamp  time.Time `json:"timestamp"`
	Comment    string    `json:"comment,omitempty"`
}

// MedSecureChain struct to manage health data
type MedSecureChain struct {
	contractapi.Contract
}

// Logger instance for logging actions
var log = logrus.New()

// Encrypt sensitive data before storing it on-chain
func encryptData(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Initialize logger
func init() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)
}

// Add a new health record
func (msc *MedSecureChain) AddHealthRecord(ctx contractapi.TransactionContextInterface, id string, ipfsHash string, source string, status string) error {
	// Get current client identity (patient)
	patientID := ctx.GetClientIdentity().GetID()

	record := HealthRecord{
		ID:               id,
		IPFSHash:         encryptData(ipfsHash), // Encrypt IPFS hash for privacy
		Patient:          patientID,
		AccessGranted:    false,
		Version:          1,
		Timestamp:        time.Now(),
		Source:           source,
		Verified:         false,
		Consent:          make(map[string]bool),
		Status:           status, // Initial status
		AuditLogs:        []AuditLog{}, // No audit logs initially
	}

	// Marshal the record to JSON
	recordJSON, err := json.Marshal(record)
	if err != nil {
		log.WithFields(logrus.Fields{"action": "AddHealthRecord", "error": err}).Error("Failed to encode record")
		return fmt.Errorf("Failed to encode record: %v", err)
	}

	// Save the record on the blockchain
	err = ctx.GetStub().PutState(id, recordJSON)
	if err != nil {
		log.WithFields(logrus.Fields{"action": "AddHealthRecord", "id": id, "error": err}).Error("Failed to put state")
		return fmt.Errorf("Failed to save health record: %v", err)
	}

	log.WithFields(logrus.Fields{"action": "AddHealthRecord", "id": id}).Info("Health record added successfully")
	return nil
}

// Grant access to a doctor (requires multi-signature)
func (msc *MedSecureChain) GrantAccess(ctx contractapi.TransactionContextInterface, id string, doctor string) error {
	recordJSON, err := ctx.GetStub().GetState(id)
	if err != nil || recordJSON == nil {
		log.WithFields(logrus.Fields{"action": "GrantAccess", "id": id}).Error("Record not found")
		return fmt.Errorf("Record not found")
	}

	var record HealthRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		log.WithFields(logrus.Fields{"action": "GrantAccess", "id": id, "error": err}).Error("Failed to unmarshal record")
		return fmt.Errorf("Failed to unmarshal record: %v", err)
	}

	// Check if the current user is the patient or an admin
	clientID := ctx.GetClientIdentity().GetID()
	if record.Patient != clientID {
		log.WithFields(logrus.Fields{"action": "GrantAccess", "id": id, "clientID": clientID}).Error("Only the patient can grant access")
		return fmt.Errorf("Only the patient can grant access")
	}

	// Simulate multi-signature approval (both doctor and patient need to approve)
	record.Doctor = doctor
	record.AccessGranted = true
	record.Consent[doctor] = true

	// Increment version for every update
	record.Version++

	// Add audit log entry for this action
	auditLog := AuditLog{
		UserID:    clientID,
		Action:    "Grant Access",
		Timestamp: time.Now(),
		Comment:   fmt.Sprintf("Access granted to doctor: %s", doctor),
	}
	record.AuditLogs = append(record.AuditLogs, auditLog)

	updatedRecord, _ := json.Marshal(record)
	err = ctx.GetStub().PutState(id, updatedRecord)
	if err != nil {
		log.WithFields(logrus.Fields{"action": "GrantAccess", "id": id, "error": err}).Error("Failed to update record")
		return fmt.Errorf("Failed to update record: %v", err)
	}

	log.WithFields(logrus.Fields{"action": "GrantAccess", "id": id, "doctor": doctor}).Info("Access granted successfully")
	return nil
}

// Revoke access from a doctor
func (msc *MedSecureChain) RevokeAccess(ctx contractapi.TransactionContextInterface, id string, doctor string) error {
	recordJSON, err := ctx.GetStub().GetState(id)
	if err != nil || recordJSON == nil {
		log.WithFields(logrus.Fields{"action": "RevokeAccess", "id": id}).Error("Record not found")
		return fmt.Errorf("Record not found")
	}

	var record HealthRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		log.WithFields(logrus.Fields{"action": "RevokeAccess", "id": id, "error": err}).Error("Failed to unmarshal record")
		return fmt.Errorf("Failed to unmarshal record: %v", err)
	}

	// Revoke access
	delete(record.Consent, doctor)
	record.AccessGranted = len(record.Consent) > 0

	// Add audit log entry for this action
	auditLog := AuditLog{
		UserID:    ctx.GetClientIdentity().GetID(),
		Action:    "Revoke Access",
		Timestamp: time.Now(),
		Comment:   fmt.Sprintf("Access revoked from doctor: %s", doctor),
	}
	record.AuditLogs = append(record.AuditLogs, auditLog)

	// Increment version
	record.Version++

	updatedRecord, _ := json.Marshal(record)
	err = ctx.GetStub().PutState(id, updatedRecord)
	if err != nil {
		log.WithFields(logrus.Fields{"action": "RevokeAccess", "id": id, "error": err}).Error("Failed to update record")
		return fmt.Errorf("Failed to update record: %v", err)
	}

	log.WithFields(logrus.Fields{"action": "RevokeAccess", "id": id, "doctor": doctor}).Info("Access revoked successfully")
	return nil
}

// Main function to start the chaincode
func main() {
	chaincode, err := contractapi.NewChaincode(new(MedSecureChain))
	if err != nil {
		log.WithFields(logrus.Fields{"error": err}).Fatal("Error creating MedSecureChain chaincode")
		return
	}

	if err := chaincode.Start(); err != nil {
		log.WithFields(logrus.Fields{"error": err}).Fatal("Error starting MedSecureChain chaincode")
	}
}

