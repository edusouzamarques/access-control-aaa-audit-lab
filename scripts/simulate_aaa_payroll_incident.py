#!/usr/bin/env python3
"""
Simulate Access Control & AAA Failures vs. Hardened Dual-Authorization (NIST AC-6 / CIS 5)
Google Cybersecurity Certificate - Course 5: Assets, Threats, and Vulnerabilities

Demonstrates:
 1. Legacy/Vulnerable State: Generic shared account, no MFA, cross-functional overprivilege (Legal -> Payroll).
 2. Hardened State: Named individual accounts, MFA token validation, RBAC enforcement, and Maker-Checker Dual-Authorization.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
import json


@dataclass
class UserSession:
    username: str
    department: str
    roles: List[str]
    is_generic_account: bool
    mfa_authenticated: bool
    workstation_name: str
    source_ip: str
    is_corporate_managed: bool


class LegacyPayrollSystem:
    """Represents the unhardened system where Event ID 1227 took place."""

    def __init__(self):
        self.audit_log: List[Dict] = []
        self.payroll_registry: List[Dict] = []

    def execute_payroll_update(self, session: UserSession, target_bank: str, amount: float) -> Dict:
        timestamp = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")

        # Flaw: Checks only if user has generic 'admin' in role, ignoring department separation
        if "admin" in [r.lower() for r in session.roles]:
            record = {
                "event_type": "Information",
                "event_source": "AdsmEmployeeService",
                "event_id": 1227,
                "timestamp": timestamp,
                "user": session.username,
                "computer": session.workstation_name,
                "ip": session.source_ip,
                "description": f"Payroll event added. {target_bank}",
                "amount": amount,
                "status": "COMMITTED_UNVERIFIED",
            }
            self.payroll_registry.append(record)
            self.audit_log.append(record)
            return {"success": True, "message": "Transaction committed without dual check", "event": record}
        else:
            return {"success": False, "message": "Denied"}


class HardenedEnterprisePayrollSystem:
    """Implements NIST SP 800-53 (AC-2, AC-3, AC-6) and CIS Controls 5/6."""

    def __init__(self):
        self.audit_log: List[Dict] = []
        self.pending_transactions: Dict[str, Dict] = {}
        self.payroll_registry: List[Dict] = []

    def request_payroll_update(
        self, session: UserSession, tx_id: str, target_bank: str, amount: float
    ) -> Dict:
        timestamp = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")

        # 1. AAA - Authentication Gate: Disallow generic accounts
        if session.is_generic_account:
            rejection = {
                "event_id": 4101,
                "timestamp": timestamp,
                "user": session.username,
                "computer": session.workstation_name,
                "reason": "POLICY_VIOLATION: Generic/shared accounts prohibited.",
            }
            self.audit_log.append(rejection)
            return {"success": False, "code": "AUTH_SHARED_ACCOUNT_BLOCKED", "detail": rejection}

        # 2. AAA - Authentication Gate: Device and MFA verification
        if not session.is_corporate_managed or not session.mfa_authenticated:
            rejection = {
                "event_id": 4102,
                "timestamp": timestamp,
                "user": session.username,
                "computer": session.workstation_name,
                "reason": "ZERO_TRUST_VIOLATION: Unmanaged host or missing MFA challenge.",
            }
            self.audit_log.append(rejection)
            return {"success": False, "code": "AUTH_MFA_DEVICE_REJECTED", "detail": rejection}

        # 3. AAA - Authorization Gate: RBAC & Separation of Duties
        if session.department.lower() != "finance" or "payroll_operator" not in session.roles:
            rejection = {
                "event_id": 4103,
                "timestamp": timestamp,
                "user": session.username,
                "department": session.department,
                "reason": "LEAST_PRIVILEGE_VIOLATION: Department not authorized for payroll disbursement.",
            }
            self.audit_log.append(rejection)
            return {"success": False, "code": "RBAC_SOD_VIOLATION", "detail": rejection}

        # 4. AAA - Dual Control / Maker-Checker Policy
        tx_data = {
            "tx_id": tx_id,
            "initiated_by": session.username,
            "target_bank": target_bank,
            "amount": amount,
            "status": "PENDING_SECONDARY_APPROVAL",
            "approvals": [session.username],
        }
        self.pending_transactions[tx_id] = tx_data
        self.audit_log.append({
            "event_id": 1228,
            "timestamp": timestamp,
            "user": session.username,
            "action": "TRANSACTION_STAGED_AWAITING_APPROVAL",
            "tx_id": tx_id,
        })
        return {"success": True, "code": "STAGED", "tx": tx_data}

    def approve_payroll_update(self, session: UserSession, tx_id: str) -> Dict:
        timestamp = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")

        if tx_id not in self.pending_transactions:
            return {"success": False, "reason": "Transaction not found"}

        tx = self.pending_transactions[tx_id]

        # Maker cannot be Checker
        if session.username in tx["approvals"]:
            return {
                "success": False,
                "reason": "DUAL_CONTROL_VIOLATION: The initiator cannot approve their own transaction.",
            }

        # Approver must be Finance Supervisor
        if session.department.lower() != "finance" or "payroll_supervisor" not in session.roles:
            return {"success": False, "reason": "RBAC_VIOLATION: Insufficient supervisor authority."}

        tx["approvals"].append(session.username)
        tx["status"] = "COMMITTED_APPROVED"
        self.payroll_registry.append(tx)
        del self.pending_transactions[tx_id]

        log_entry = {
            "event_id": 1227,
            "timestamp": timestamp,
            "maker": tx["initiated_by"],
            "checker": session.username,
            "target_bank": tx["target_bank"],
            "amount": tx["amount"],
            "status": "COMMITTED_APPROVED",
        }
        self.audit_log.append(log_entry)
        return {"success": True, "code": "APPROVED_AND_EXECUTED", "audit": log_entry}


def main():
    print("=" * 80)
    print(" ACCESS CONTROL & AAA AUDIT LAB: EVENT 1227 RECONSTRUCTION & MITIGATION")
    print("=" * 80)

    # -------------------------------------------------------------
    # Scenario 1: Simulating Vulnerable State (The Actual Incident)
    # -------------------------------------------------------------
    legacy_system = LegacyPayrollSystem()
    rogue_session = UserSession(
        username=r"Legal\Administrator",
        department="Legal",
        roles=["admin"],
        is_generic_account=True,
        mfa_authenticated=False,
        workstation_name="Up2-NoGud",
        source_ip="152.207.255.255",
        is_corporate_managed=False,
    )

    print("\n[!] SCENARIO 1: Vulnerable System Execution (Event ID 1227 Reproduction)...")
    res1 = legacy_system.execute_payroll_update(
        session=rogue_session,
        target_bank="FAUX_BANK",
        amount=18500.00,
    )
    print(f"Outcome: {res1['message']}")
    print("Event Log Generated:")
    print(json.dumps(res1["event"], indent=2))

    # -------------------------------------------------------------
    # Scenario 2: Hardened Zero Trust + RBAC + Dual Control Defense
    # -------------------------------------------------------------
    hardened_system = HardenedEnterprisePayrollSystem()
    print("\n" + "-" * 80)
    print("[*] SCENARIO 2: Re-running Incident Against Hardened Security Controls...")

    # Test 2a: Rogue Legal\\Administrator attempts exploit
    print("\n-> [Test 2a] Rogue session attempt (Legal\\Administrator / Up2-NoGud)...")
    res2a = hardened_system.request_payroll_update(
        session=rogue_session,
        tx_id="TX-9901",
        target_bank="FAUX_BANK",
        amount=18500.00,
    )
    print(f"Result: {res2a['code']}")
    print(f"Audit: {json.dumps(res2a['detail'], indent=2)}")

    # Test 2b: Legitimate Finance Maker requests payroll change
    finance_maker = UserSession(
        username="carol.danvers",
        department="Finance",
        roles=["payroll_operator"],
        is_generic_account=False,
        mfa_authenticated=True,
        workstation_name="CORP-FIN-004",
        source_ip="10.20.4.15",
        is_corporate_managed=True,
    )
    print("\n-> [Test 2b] Authorized Finance Operator submits change (Single approval)...")
    res2b = hardened_system.request_payroll_update(
        session=finance_maker,
        tx_id="TX-9902",
        target_bank="CHASE_PAYROLL_ESCROW",
        amount=18500.00,
    )
    print(f"Status: {res2b['tx']['status']} (Requires 2nd human approval)")

    # Test 2c: Finance Supervisor provides second authorization
    finance_supervisor = UserSession(
        username="elena.rostova",
        department="Finance",
        roles=["payroll_supervisor"],
        is_generic_account=False,
        mfa_authenticated=True,
        workstation_name="CORP-FIN-001",
        source_ip="10.20.4.10",
        is_corporate_managed=True,
    )
    print("\n-> [Test 2c] Finance Supervisor approves via Dual-Authorization protocol...")
    res2c = hardened_system.approve_payroll_update(
        session=finance_supervisor,
        tx_id="TX-9902",
    )
    print(f"Result: {res2c['code']}")
    print(f"Audit Trail: {json.dumps(res2c['audit'], indent=2)}")

    print("\n" + "=" * 80)
    print(" AUDIT VERDICT: 100% MITIGATION OF EVENT 1227 VULNERABILITIES")
    print("=" * 80)


if __name__ == "__main__":
    main()
