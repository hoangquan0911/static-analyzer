// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyContract {

    mapping(address => uint256) public balances;

    constructor() payable {}

    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Integer overflow vulnerability
    function deposit(uint256 amount) public {
        balances[msg.sender] += amount;
    }

    // Unchecked external call vulnerability
    function sendEther(address payable recipient, uint256 amount) public {
        recipient.call{value: amount}("");
    }

    // Usage of deprecated tx.origin
    function checkSender() public view returns (bool) {
        return tx.origin == msg.sender;
    }

    fallback() external payable {}
}
