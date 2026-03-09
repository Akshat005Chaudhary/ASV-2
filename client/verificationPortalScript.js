async function verifyCertificate() {

  const studentWallet = document.getElementById("walletAddress").value.trim();
  const cid = document.getElementById("ipfsHash").value.trim();
  const timestamp = document.getElementById("timestamp").value.trim();

  const resultDiv = document.getElementById("verificationResult");
  resultDiv.innerHTML = "Verifying certificate...";

  if (!studentWallet || !cid || !timestamp) {
    resultDiv.innerHTML = "Please fill all fields.";
    return;
  }

  try {

    const response = await fetch("http://127.0.0.1:3000/verifyCertificate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        studentWallet,
        cid,
        timestamp
      })
    });

    const result = await response.json();

    if (!response.ok) {
      resultDiv.innerHTML = "No Verification Record Found. Wrong Credentials?";
      return;
    }

    if (!result.valid) {

      resultDiv.innerHTML = `
        <h3 style="color:red;">Certificate NOT found on blockchain.</h3>
      `;

      return;
    }


    resultDiv.innerHTML = `
      <h3 style="color:green;">Certificate Verified ✔</h3>
      <strong>Issued To:</strong> ${result.student}<br>
      <strong>Issued By:</strong> ${result.issuer}<br>
      <strong>Timestamp:</strong> ${result.timestamp}<br><br>
      <a href="http://127.0.0.1:8081/ipfs/${result.cid}" target="_blank">
        View Certificate
      </a>
    `;

  } catch (error) {

    console.error(error);

    resultDiv.innerHTML = "Server error during verification.";

  }

}