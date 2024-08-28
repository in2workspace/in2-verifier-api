function switchToSameDeviceLogin() {
    document.getElementById('qr-title').style.display = 'none';
    document.getElementById('qr-code').style.display = 'none';
    document.getElementById('same-device-title').style.display = 'block';
    document.getElementById('dome-wallet-button').style.display = 'flex';
    document.getElementById('grey-section-text').innerHTML = 'Switch to <a href="#" onclick="switchToQRLogin()">QR code login</a>';
}

function switchToQRLogin() {
    document.getElementById('qr-title').style.display = 'block';
    document.getElementById('qr-code').style.display = 'block';
    document.getElementById('same-device-title').style.display = 'none';
    document.getElementById('dome-wallet-button').style.display = 'none';
    document.getElementById('grey-section-text').innerHTML = 'Unable to scan the QR code? You may log in from the <a href="#" onclick="switchToSameDeviceLogin()">same device</a>';
}

function decodeQR() {
    const img = document.getElementById('qr-code');
    const walletButton = document.getElementById('dome-wallet-button');
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    img.onload = () => {
        canvas.width = img.naturalWidth;
        canvas.height = img.naturalHeight;
        context.drawImage(img, 0, 0, canvas.width, canvas.height);
        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code) {
            const baseUrl = 'https://wallet.dome-marketplace-dev2.org/tabs/home';
            const qrData = code.data.replace('openid://', '');
            walletButton.onclick = () => window.location.href = `${baseUrl}${qrData}`;
        }
    };
    img.onerror = () => {
        console.error('Error loading image.');
    };
}

document.addEventListener('DOMContentLoaded', () => {
    decodeQR();
});