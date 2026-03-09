let contract;
let account;
let universityAccount;
let authJWT = null;

/* =========================
  IAM + MFA (connecting wallet)
========================= */

async function connectWallet() {

  const web3 = new Web3(window.ethereum);

  await window.ethereum.request({ method: "eth_requestAccounts" });

  account = (await web3.eth.getAccounts())[0];

  console.log("Connected Certificate Issuer Account:", account);

  universityAccount = account.toString();

  const contractJson = await fetch("../build/contracts/CertificateStorage.json")
    .then(res => res.json());

  const contractAddress = "0x161c312E4007669d7457ed5345950483E59B1a37";

  contract = new web3.eth.Contract(contractJson.abi, contractAddress);

  console.log("Contract loaded.");

  checkIAM();
}

async function checkIAM() {

  const response = await fetch("http://localhost:3000/iam/check", {

    method: "POST",

    headers: {
      "Content-Type": "application/json"
    },

    body: JSON.stringify({
      issuerWallet: universityAccount
    })

  });

  const result = await response.json();

  if (response.status !== 200) {

    alert("This wallet is NOT a registered university.");

    return;

  }

  console.log("University authorized:", result);

  alert("University verified.");

  requestMFA();   // start MFA challenge
}

async function requestMFA() {

  const response = await fetch("http://localhost:3000/mfa/request", {

    method: "POST",

    headers: {
      "Content-Type": "application/json"
    },

    body: JSON.stringify({
      issuerWallet: universityAccount
    })

  });

  const result = await response.json();

  if (response.status !== 200) {

    alert("Failed to send OTP");

    return;

  }

  alert("OTP sent to registered university email.");

  const otp = prompt("Enter the OTP sent to your email:");

  verifyMFA(otp);
}

async function verifyMFA(otp) {

  const response = await fetch("http://localhost:3000/mfa/verify", {

    method: "POST",

    headers: {
      "Content-Type": "application/json"
    },

    body: JSON.stringify({
      issuerWallet: universityAccount,
      otp: otp
    })

  });

  const result = await response.json();

  if (response.status !== 200) {

    alert("OTP verification failed.");

    return;

  }

  authJWT = result.authJWT;

  console.log("Authentication token:", authJWT);

  alert("MFA verified. You may now issue certificates.");

}

/* =========================
  Certificate Uploading to IPFS
========================= */

async function uploadToIPFS(file) {
  try {
    const ipfs = KuboRpcClient.create({ url: "http://localhost:5001/api/v0" });
    const added = await ipfs.add(file);
    return added.cid.toString();
  } catch (err) {
    console.error("IPFS upload failed:", err);
    throw err;
  }
}

async function uploadCert() {

  if (!authJWT) {
    alert("Please complete authentication first.");
    return;
  }

  const file = document.getElementById("certFile").files[0];
  const studentWallet = document.getElementById("studentWallet").value.trim();

  if (!file || !studentWallet) {
    alert("Please select a file and enter student wallet address.");
    return;
  }

  try {

    const ipfsHash = await uploadToIPFS(file);

    console.log("IPFS Hash (CID):", ipfsHash);

    alert("Certificate uploaded. CID: " + ipfsHash);

    /* =============================
       Step 1: Create payload
    ============================= */

    const timestamp = Date.now();

    const web3 = new Web3(window.ethereum);

    const payloadHash = web3.utils.soliditySha3(
      { type: "address", value: studentWallet },
      { type: "string", value: ipfsHash },
      { type: "uint256", value: timestamp }
    );

    console.log("Payload Hash:", payloadHash);

    /* =============================
       Step 2: Sign payload hash
    ============================= */

    const signature = await web3.eth.personal.sign(
      payloadHash,
      universityAccount,
      ""
    );

    console.log("Signature:", signature);

    /* =============================
       Step 3: Send to backend
    ============================= */

    const response = await fetch("http://localhost:3000/certificate/issue", {

      method: "POST",

      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + authJWT
      },

      body: JSON.stringify({

        issuerWallet: universityAccount,
        studentWallet: studentWallet,
        cid: ipfsHash,
        timestamp: timestamp,
        payloadHash: payloadHash,
        signature: signature

      })

    });

    const result = await response.json();

    if (response.status !== 200) {

      alert("Certificate issuance failed");

      console.error(result);

      return;

    }

    alert("Certificate successfully registered on blockchain.");

  } catch (error) {

    console.error("Upload error:", error);

    alert("Error uploading certificate. Check console for details.");

  }
}