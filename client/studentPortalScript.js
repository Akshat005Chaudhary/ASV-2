async function fetchCertificates() {

  const walletAddress = document.getElementById("studentWallet").value.trim();

  if (!walletAddress) {
    alert("Please enter a wallet address.");
    return;
  }

  const display = document.getElementById("certificatesDisplayResult");
  display.innerHTML = "Loading certificates...";

  try {

    const response = await fetch(
      `http://127.0.0.1:3000/studentCertificates/${walletAddress}`
    );

    if (!response.ok) {
      throw new Error("Server returned error");
    }

    const certificates = await response.json();

    display.innerHTML = "";

    if (!certificates || certificates.length === 0) {
      display.innerHTML = "No certificates found.";
      return;
    }

    certificates.forEach(cert => {

      const certElement = document.createElement("div");

      certElement.style.border = "1px solid #ccc";
      certElement.style.padding = "10px";
      certElement.style.marginBottom = "10px";

      certElement.innerHTML = `
        <strong>Certificate PayloadHash:</strong> ${cert.payloadHash}<br>
        <strong>IPFS CID:</strong> ${cert.cid}<br>
        <strong>Student:</strong> ${cert.student}<br>
        <strong>Issuer:</strong> ${cert.issuer}<br>
        <strong>Issued At:</strong> ${cert.timestamp}<br>
        <strong>View Certificate:</strong>
        <a href="http://127.0.0.1:8081/ipfs/${cert.cid}" target="_blank">
          Open Certificate
        </a>
      `;

      display.appendChild(certElement);

    });

  } catch (error) {

    console.error("Fetch error:", error);

    display.innerHTML = "Error fetching certificates.";

  }

}