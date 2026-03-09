// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertificateStorage {

    struct Certificate {
        bytes32 payloadHash;
        string cid;
        address student;
        address issuer;
        uint256 issuedAt;
    }

    mapping(bytes32 => Certificate) public certificates;

    bytes32[] public certificateHashes;

    mapping(address => bool) public isRegisteredUniversity;

    constructor() {
        isRegisteredUniversity[0xAeB5Dc5d5DbfdF3E9291C942cF4431844d902BeD] = true;
    }

    function registerCertificate(bytes32 payloadHash, string memory cid, address student, uint256 issuedAt) public {

        require(isRegisteredUniversity[msg.sender], "Not a registered university");

        certificates[payloadHash] = Certificate({
            payloadHash: payloadHash,
            cid: cid,
            student: student,
            issuer: msg.sender,
            issuedAt: issuedAt
        });

        certificateHashes.push(payloadHash);
    }

    function totalCertificates() public view returns (uint) {
        return certificateHashes.length;
    }

    function getCertificate(uint index) public view returns (
        bytes32 payloadHash,
        string memory cid,
        address student,
        address issuer,
        uint256 issuedAt
    ) {

        require(index < certificateHashes.length, "Invalid index");

        bytes32 hash = certificateHashes[index];

        Certificate memory cert = certificates[hash];

        return (
            cert.payloadHash,
            cert.cid,
            cert.student,
            cert.issuer,
            cert.issuedAt
        );
    }
}