// Función para cambiar al flujo de "same device"
function switchToSameDeviceLogin() {
    document.getElementById('qr-title').style.display = 'none';
    document.getElementById('qr-code').style.display = 'none';
    document.getElementById('same-device-title').style.display = 'block';
    document.getElementById('dome-wallet-button').style.display = 'flex';
    document.getElementById('grey-section-text').innerHTML = 'Switch to <a href="#" onclick="switchToQRLogin()">QR code login</a>';
}

// Función para cambiar al flujo de QR
function switchToQRLogin() {
    document.getElementById('qr-title').style.display = 'block';
    document.getElementById('qr-code').style.display = 'block';
    document.getElementById('same-device-title').style.display = 'none';
    document.getElementById('dome-wallet-button').style.display = 'none';
    document.getElementById('grey-section-text').innerHTML = 'Unable to scan the QR code? You may log in from the <a href="#" onclick="switchToSameDeviceLogin()">same device</a>';
}

// Función para configurar el enlace del botón con el authRequest
function configureAuthRequest() {
    const walletButton = document.getElementById('dome-wallet-button');
    if (authRequest) {
        let walletUri = authRequest.replace("openid4vp://", "https://wallet.dome-marketplace.org");
        walletButton.onclick = () => window.location.href = walletUri;
    }
}

// Evento que se activa cuando el DOM ha cargado
document.addEventListener('DOMContentLoaded', () => {
    configureAuthRequest();
});

