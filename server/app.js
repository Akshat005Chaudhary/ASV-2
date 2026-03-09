const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const Web3 = require("web3");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(cors());

const universities = require("./universityAccounts.json");

const web3 = new Web3("http://127.0.0.1:7545");

const contractJson = require("../build/contracts/CertificateStorage.json");

const networkId = Object.keys(contractJson.networks)[0];

const contract = new web3.eth.Contract(
  contractJson.abi,
  contractJson.networks[networkId].address
);

const otpStore = new Map();

function getUniversityEmail(wallet) {

  const uni = universities.find(
    u => u.wallet.toLowerCase() === wallet.toLowerCase()
  );

  return uni ? uni.email : null;

}

const transporter = nodemailer.createTransport({
  secure: true,
  host: 'smtp.gmail.com',
  port: 465,
  auth:{
    user: 'chaudharyakshat555@gmail.com',
    pass: 'fjnb frvs kram epan'
  }
});

/* =========================
   IAM CHECK
========================= */

app.post("/iam/check", async (req, res) => {

  const { issuerWallet } = req.body;

  const isRegistered = await contract.methods
    .isRegisteredUniversity(issuerWallet)
    .call();

  if (!isRegistered) {

    return res.status(403).json({
      message: "Issuer not authorized"
    });

  }

  res.json({
    message: "Issuer authorized"
  });

});

/* =========================
   MFA REQUEST
========================= */

app.post("/mfa/request", async (req, res) => {

  const { issuerWallet } = req.body;

  const isRegistered = await contract.methods
    .isRegisteredUniversity(issuerWallet)
    .call();

  if (!isRegistered)
    return res.status(403).send("Not a registered university");

  const email = getUniversityEmail(issuerWallet);

  if (!email)
    return res.status(400).send("University email not found");

  const otp = Math.floor(100000 + Math.random() * 900000);

  const expiry = Date.now() + 5 * 60 * 1000;

  const hashedOTP = crypto
    .createHash("sha256")
    .update(otp.toString())
    .digest("hex");

  otpStore.set(issuerWallet, {
    otp: hashedOTP,
    expiry
  });

/* =========================
   SEND OTP TO MAIL VIA NODEMAILER
========================= */

const mailOptions = {
  from: "chaudharyakshat555@gmail.com",
  to: email,
  subject: "University MFA Verification Code",
  text: `Your OTP for certificate issuance is: ${otp}. This OTP will expire in 5 minutes.`
};

try {

  await transporter.sendMail(mailOptions);

  console.log("OTP email sent to:", email);

} catch (error) {

  console.error("Error sending email:", error);

  return res.status(500).send("Failed to send OTP email");

}

  res.json({
    message: "OTP sent to university email"
  });

});

/* =========================
   MFA VERIFY
========================= */

app.post("/mfa/verify", (req, res) => {

  const { issuerWallet, otp } = req.body;

  const record = otpStore.get(issuerWallet);

  if (!record)
    return res.status(400).send("OTP not requested");

  if (Date.now() > record.expiry)
    return res.status(400).send("OTP expired");

  const hashed = crypto
    .createHash("sha256")
    .update(otp.toString())
    .digest("hex");

  if (hashed !== record.otp)
    return res.status(400).send("Invalid OTP");

  const authJWT = jwt.sign(
    { issuerWallet },
    "superSecretKey",
    { expiresIn: "10m" }
  );

  otpStore.delete(issuerWallet);

  res.json({
    authJWT
  });

});


/* =========================
   Digital Signature Verification
========================= */


app.post("/certificate/issue", async (req, res) => {

  try {

    /* =========================
       STEP 1: Verify JWT
    ========================= */

    const authHeader = req.headers.authorization;

    if (!authHeader)
      return res.status(401).send("Missing auth token");

    const token = authHeader.split(" ")[1];

    let decoded;

    try {

      decoded = jwt.verify(token, "superSecretKey");

    } catch (err) {

      return res.status(401).send("Invalid or expired token");

    }

    const jwtIssuer = decoded.issuerWallet;

    /* =========================
       STEP 2: Extract request body
    ========================= */

    const {
      issuerWallet,
      studentWallet,
      cid,
      timestamp,
      payloadHash,
      signature
    } = req.body;

    if (jwtIssuer.toLowerCase() !== issuerWallet.toLowerCase())
      return res.status(403).send("JWT issuer mismatch");

    /* =========================
       STEP 3: Recompute payload hash
    ========================= */

    const reconstructedHash = web3.utils.soliditySha3(
      { type: "address", value: studentWallet },
      { type: "string", value: cid },
      { type: "uint256", value: timestamp }
    );

    if (reconstructedHash !== payloadHash)
      return res.status(400).send("Payload hash mismatch");

    /* =========================
       STEP 4: Recover signer
    ========================= */

    const recoveredWallet = web3.eth.accounts.recover(
      payloadHash,
      signature
    );

    if (recoveredWallet.toLowerCase() !== issuerWallet.toLowerCase())
      return res.status(403).send("Invalid signature");

    /* =========================
       STEP 5: Register on blockchain
    ========================= */

    const receipt = await contract.methods
      .registerCertificate(payloadHash, cid, studentWallet)
      .send({ from: issuerWallet });

    res.json({
      message: "Certificate registered successfully",
      transactionHash: receipt.transactionHash
    });

  } catch (error) {

    console.error("Issuance error:", error);

    res.status(500).send("Server error during certificate issuance");

  }

});


/* =========================
  Student Portal Server Handling
========================= */

app.get("/studentCertificates/:walletAddress", async (req, res) => {

  try {

    const walletAddress = req.params.walletAddress.toLowerCase();

    console.log("Querying certificates for wallet:", walletAddress);

    const total = await contract.methods.totalCertificates().call();

    const certificates = [];

    for (let i = 0; i < total; i++) {

      const cert = await contract.methods.getCertificate(i).call();

      const certObj = {
        payloadHash: cert[0],
        cid: cert[1],
        student: cert[2],
        issuer: cert[3],
        timestamp: cert[4]
      };

      if (certObj.student.toLowerCase() === walletAddress) {
        certificates.push(certObj);
      }


    }
    const serializedCertificates = certificates.map((cert) => {
      return {
        ...cert,
        timestamp: cert.timestamp.toString(),
      };
    });
    res.send(serializedCertificates);

  } catch (error) {

    console.error("Student certificate query error:", error);

    res.status(500).json({
      error: "Failed to fetch certificates"
    });

  }

});


/* =========================
   Verification Portal Server Handling
========================= */

app.post("/verifyCertificate", async (req, res) => {

  try {

    const { studentWallet, cid, timestamp } = req.body;

    /* =============================
       Reconstruct payload hash
    ============================= */

    const payloadHash = web3.utils.soliditySha3(
      { type: "address", value: studentWallet },
      { type: "string", value: cid },
      { type: "uint256", value: timestamp }
    );

    /* =============================
       Query smart contract
    ============================= */

    const cert = await contract.methods
      .certificates(payloadHash)
      .call();

    /* =============================
       Check if certificate exists
    ============================= */

    if (cert.issuer === "0x0000000000000000000000000000000000000000") {

      return res.json({
        valid: false
      });

    }

    /* =============================
       Validate fields match
    ============================= */

    if (
      cert.student.toLowerCase() !== studentWallet.toLowerCase() ||
      cert.cid !== cid ||
      cert.issuedAt.toString() !== timestamp.toString()
    ) {

      return res.json({
        valid: false
      });

    }

    /* =============================
       Return verification success
    ============================= */

    res.json({
      valid: true,
      student: cert.student,
      issuer: cert.issuer,
      timestamp: cert.issuedAt.toString(),
      cid: cert.cid
    });

  } catch (error) {

    console.error("Verification error:", error);

    res.status(500).json({
      valid: false
    });

  }

});


/* =========================
   SERVER START
========================= */

app.listen(3000, () => {
  console.log("Server running on port 3000");
});