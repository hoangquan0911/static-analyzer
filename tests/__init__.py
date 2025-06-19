"""
Testing framework for the Solidity Static Analyzer.

This module provides comprehensive testing utilities and fixtures
for testing detectors and analyzer functionality.
"""

import os
import tempfile
from pathlib import Path
from typing import List, Dict, Any


class TestContract:
    """Helper class for creating test contracts."""
    
    def __init__(self, name: str, content: str):
        self.name = name
        self.content = content
    
    def write_to_file(self, directory: str = None) -> str:
        """Write the contract to a temporary file."""
        if directory is None:
            directory = tempfile.mkdtemp()
        
        file_path = os.path.join(directory, f"{self.name}.sol")
        with open(file_path, 'w') as f:
            f.write(self.content)
        
        return file_path


class VulnerabilityTest:
    """Base class for vulnerability tests."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.contracts: List[TestContract] = []
        self.expected_findings: List[Dict[str, Any]] = []
    
    def add_contract(self, contract: TestContract) -> 'VulnerabilityTest':
        """Add a test contract."""
        self.contracts.append(contract)
        return self
    
    def expect_finding(self, finding_type: str, severity: str = "MEDIUM", 
                      message: str = None, line: int = None) -> 'VulnerabilityTest':
        """Add an expected finding."""
        self.expected_findings.append({
            "type": finding_type,
            "severity": severity,
            "message": message,
            "line": line
        })
        return self
    
    def run_test(self, analyzer) -> bool:
        """Run the test and return True if all expected findings are found."""
        # Create temporary directory for test contracts with meaningful name
        test_name = self.name.replace(" ", "_").replace(".", "_").lower()
        # Remove any special characters and keep it simple
        test_name = ''.join(c for c in test_name if c.isalnum() or c == '_')
        temp_dir = tempfile.mkdtemp(prefix=f"test_{test_name}_")
        
        try:
            # Write contracts to files
            contract_files = []
            for contract in self.contracts:
                file_path = contract.write_to_file(temp_dir)
                contract_files.append(file_path)
            
            # Run analysis
            results = analyzer.analyze_with_summary(temp_dir)
            findings = results["collector"]
            
            # Check if all expected findings are present
            found_count = 0
            for expected in self.expected_findings:
                for finding in findings:
                    if (finding.type == expected["type"] and 
                        finding.severity.value == expected["severity"]):
                        if expected["line"] is None or finding.line_number == expected["line"]:
                            found_count += 1
                            break
            
            return found_count == len(self.expected_findings)
        finally:
            # Clean up temporary directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


# Predefined test contracts
REENTRANCY_VULNERABLE = TestContract(
    "ReentrancyVulnerable",
    """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] = 0;  // State change after external call
    }
}
"""
)

SIGNATURE_REPLAY_VULNERABLE = TestContract(
    "SignatureReplayVulnerable",
    """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignatureReplayVulnerable {
    function verifySignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
    
    function executeWithSignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
        address signer = verifySignature(hash, v, r, s);
        require(signer != address(0));
        // No replay protection
    }
}
"""
)

TX_ORIGIN_VULNERABLE = TestContract(
    "TxOriginVulnerable",
    """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginVulnerable {
    function withdraw() public {
        require(tx.origin == msg.sender);  // Dangerous tx.origin usage
    }
}
"""
)

# Test suite
def create_test_suite() -> List[VulnerabilityTest]:
    """Create a comprehensive test suite."""
    tests = []
    
    # Reentrancy test
    reentrancy_test = VulnerabilityTest(
        "Reentrancy Detection",
        "Test that reentrancy vulnerabilities are detected"
    ).add_contract(REENTRANCY_VULNERABLE).expect_finding(
        "Reentrancy", "HIGH", "Potential reentrancy via `.call()` with options."
    )
    tests.append(reentrancy_test)
    
    # Signature replay test
    signature_test = VulnerabilityTest(
        "Signature Replay Detection",
        "Test that signature replay vulnerabilities are detected"
    ).add_contract(SIGNATURE_REPLAY_VULNERABLE).expect_finding(
        "Signature Replay", "CRITICAL", "Signature verification detected without replay protection."
    )
    tests.append(signature_test)
    
    # tx.origin test
    tx_origin_test = VulnerabilityTest(
        "tx.origin Detection",
        "Test that tx.origin usage is detected"
    ).add_contract(TX_ORIGIN_VULNERABLE).expect_finding(
        "tx.origin Usage", "MEDIUM", "Avoid using `tx.origin` for authorization."
    )
    tests.append(tx_origin_test)
    
    return tests
